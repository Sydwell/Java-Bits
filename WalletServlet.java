package piuk.website;


import com.dropbox.client2.DropboxAPI;
import com.dropbox.client2.session.AccessTokenPair;
import com.dropbox.client2.session.AppKeyPair;
import com.dropbox.client2.session.RequestTokenPair;
import com.dropbox.client2.session.Session.AccessType;
import com.dropbox.client2.session.WebAuthSession;
import com.dropbox.client2.session.WebAuthSession.WebAuthInfo;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.googleapis.auth.oauth2.*;
import com.google.api.client.http.ByteArrayContent;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson.JacksonFactory;
import com.google.api.services.drive.Drive;
import com.google.api.services.drive.model.File;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.Phonenumber;
import com.yubico.client.v2.YubicoClient;
import com.yubico.client.v2.YubicoResponse;
import com.yubico.client.v2.YubicoResponseStatus;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.util.encoders.Hex;
import org.json.JSONArray;
import org.json.simple.JSONObject;
import org.jsoup.Jsoup;
import piuk.api.*;
import piuk.beans.*;
import piuk.common.Pair;
import piuk.common.Scrambler;
import piuk.db.BitcoinCache;
import piuk.db.BitcoinDatabaseManager;
import piuk.db.Cache;
import piuk.gauth.Base32String;
import piuk.gauth.OtpProvider;
import piuk.gauth.OtpSourceException;
import piuk.jsp.Format;
import piuk.strings.Language;
import piuk.website.admin.AdminServlet;
import piuk.website.admin.LanguageManager;
import piuk.website.admin.RequestLimiter;
import piuk.website.admin.Settings;
import piuk.website.admin.operations.ProcessForwardsOperation;

import javax.mail.internet.InternetAddress;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Servlet implementation class ChartsServlet
 */
@WebServlet({ HomeServlet.ROOT + "wallet/*", HomeServlet.ROOT + "pwallet/*" })
public class WalletServlet extends BaseServlet {
    public static final long serialVersionUID = 1L;

    public static final int LoggingLevelNone = 0;
    public static final int LoggingLevelHashed = 1;
    public static final int LoggingLevelFull = 2;

    public static final int AuthTypeStandard = 0;
    public static final int AuthTypeYubikey = 1;
    public static final int AuthTypeEmail = 2;
    public static final int AuthTypeYubikeyMtGox = 3;
    public static final int AuthTypeGoogleAuthenticator = 4;
    public static final int AuthTypeSMS = 5;

    public static final int NotificationsTypeEmail          = 1 << 0; // 1
    public static final int NotificationsTypeGoogleTalk     = 1 << 1; // 2
    public static final int NotificationsTypeHTTPPost       = 1 << 2; // 4
    public static final int NotificationsTypeSkype          = 1 << 3; // 8
    public static final int NotificationsTypeTwitter        = 1 << 4; // 16
    public static final int NotificationsTypeSMS            = 1 << 5; // 32
    public static final int NotificationsTypeBoxcar         = 1 << 6; // 64

    public static final String DemoAccountGUID = "abcaa314-6f67-6705-b384-5d47fbe9d7cc";

    private static final int MaxFailedLogins = 4;
    private static final int EmailCodeLength = 5;
    private static final int SMSCodeLength = EmailCodeLength;
    private static final int GoogleAuthentictorSecretSize = 14; //128 bits
    private static final int MaxBackupsInOneDay = 10; //128 bits
    public static final int MaxEmailsInOneDay = 30; //128 bits

    final static private String DROPBOX_APP_KEY = Settings.instance().getString("dropbox_app_key");
    final static private String DROPBOX_APP_SECRET = Settings.instance().getString("dropbox_app_secret");
    final static private AccessType DROPBOX_ACCESS_TYPE = AccessType.APP_FOLDER;
    final static private String DROPBOX_CACHE_PREFIX = "drop:";
    final static private String DROPBOX_CALLBACK = HTTPS_ROOT + "wallet/dropbox-update";

    public static final JsonFactory GDRIVE_JSON_FACTORY = new JacksonFactory();
    public static final HttpTransport GDRIVE_TRANSPORT = new NetHttpTransport();
    public static final String CLIENT_SECRETS_FILE_PATH  = "/client_secrets.json";
    public static GoogleClientSecrets GDRIVE_SECRETS; //Initizialized by ContextListener
    public static final List<String> GDRIVE_SCOPES = Arrays.asList(
            "https://www.googleapis.com/auth/drive.file",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile");

    final static private String GDRIVE_CACHE_PREFIX = "drop:";
    final static int DROPBOX_CACHE_EXPIRY = 2629743; //1 Month
    final static String TEMP_GUID_KEY = "cguid"; //1 Month
    public final static String SAVED_GUID_KEY = "saved_guid"; //1 Month
    final static String SAVED_AUTH_TYPE_KEY = "saved_auth_type"; //1 Month

    final public static int MaxAddresses = 1000;

    public static class GoogleAuthenticator {
        public static String generateSecret() {
            SecureRandom random = new SecureRandom();
            byte bytes[] = new byte[32];
            random.nextBytes(bytes);

            byte[] secretKey = Arrays.copyOf(bytes, GoogleAuthentictorSecretSize);

            return Base32String.encode(secretKey);
        }

        public static String getQRBarcodeURL(String user, String host, String secret) {
            return "otpauth://totp/"+user+"@"+host+"?secret="+secret;
        }

        public static boolean check_code(String secret, long code, int window) throws NoSuchAlgorithmException, InvalidKeyException, OtpSourceException {
            OtpProvider provider = new OtpProvider();

            // Window is used to check codes generated in the near past.
            // You can use this value to tune how far you're willing to go.
            for (int i = -window; i <= window; ++i) {
                long hash = 0;

                try {
                    hash = Long.valueOf(provider.getTOTPCode(secret, i));
                } catch (Exception e) { }

                if (hash == code) {
                    return true;
                }
            }
            // The validation code is invalid.
            return false;
        }
    }

    public static class DropBoxCacheEntry implements Serializable {
        private static final long serialVersionUID = 5L;
        private final String guid;
        private final String key;
        private final String secret;
        private String accessTokenKey;
        private String accessTokenSecret;

        public DropBoxCacheEntry(String guid, String key, String secret) {
            super();
            this.guid = guid;
            this.key = key;
            this.secret = secret;
        }

        public AccessTokenPair getAccessToken() {
            if (accessTokenKey == null || accessTokenSecret == null)
                return null;

            return new AccessTokenPair(accessTokenKey, accessTokenSecret);
        }

        public void setAccessToken(AccessTokenPair accessToken) {
            this.accessTokenKey = accessToken.key;
            this.accessTokenSecret = accessToken.secret;
        }

        public String getGuid() {
            return guid;
        }

        public String getKey() {
            return key;
        }

        public String getsecret() {
            return secret;
        }
    }


    protected static boolean doGDriveBackup(String guid, String code) {

        try {
            String refreshToken = (String) Cache.get(GDRIVE_CACHE_PREFIX + code);

            Credential credentials = null;
            if (refreshToken != null) {
                credentials =  new GoogleCredential.Builder()
                        .setClientSecrets(GDRIVE_SECRETS)
                        .setTransport(GDRIVE_TRANSPORT)
                        .setJsonFactory(GDRIVE_JSON_FACTORY)
                        .build().setRefreshToken(refreshToken);
            } else {
                GoogleTokenResponse response =
                        new GoogleAuthorizationCodeTokenRequest(
                                GDRIVE_TRANSPORT,
                                GDRIVE_JSON_FACTORY,
                                GDRIVE_SECRETS.getWeb().getClientId(),
                                GDRIVE_SECRETS.getWeb().getClientSecret(),
                                code,
                                GDRIVE_SECRETS.getWeb().getRedirectUris().get(0)).execute();

                credentials =  new GoogleCredential.Builder()
                        .setClientSecrets(GDRIVE_SECRETS)
                        .setTransport(GDRIVE_TRANSPORT)
                        .setJsonFactory(GDRIVE_JSON_FACTORY)
                        .build().setFromTokenResponse(response);

                Cache.put(GDRIVE_CACHE_PREFIX + code, credentials.getRefreshToken(), DROPBOX_CACHE_EXPIRY);
            }

            Drive drive = Drive.builder(GDRIVE_TRANSPORT, GDRIVE_JSON_FACTORY).setHttpRequestInitializer(credentials).build();

            String payload = null;

            Connection conn = BitcoinDatabaseManager.conn();
            try {
                PreparedStatement selectPayload = conn.prepareStatement("select payload from bitcoin_wallets where guid = ?");
                try {
                    selectPayload.setString(1, guid);

                    ResultSet results = selectPayload.executeQuery();

                    if (results.next()) {

                        payload = results.getString(1);
                    } else {
                        throw new Exception("Unauthorized");
                    }

                } finally {
                    BitcoinDatabaseManager.close(selectPayload);
                }
            } finally {
                BitcoinDatabaseManager.close(conn);
            }

            if (payload != null && payload.length() > 0) {
                SimpleDateFormat format = new SimpleDateFormat("dd_MM_yyyy_HH_mm_ss");

                String dateString = format.format(new Date());

                String fileName = "wallet_"+dateString+".aes.json";

                File file = new File();
                file.setId(fileName);
                file.setTitle(fileName);
                file.setDescription(fileName);
                file.setMimeType("text/plain");

                drive.files().insert(file, new ByteArrayContent("text/plain", payload.getBytes("UTF-8"))).execute();

                return true;
            } else {
                throw new Exception("Null payload");
            }

        } catch (Exception e) {
            return false;
        }
    }

    protected static boolean doDropboxBackup(String oauth_token) {
        try {
            DropBoxCacheEntry entry = (DropBoxCacheEntry) Cache.get(DROPBOX_CACHE_PREFIX + oauth_token);

            if (entry == null) {
                throw new Exception("Could not find dropbox authentication session");
            }

            AppKeyPair appKeys = new AppKeyPair(DROPBOX_APP_KEY, DROPBOX_APP_SECRET);

            WebAuthSession dropboxSession = null;

            if (entry.getAccessToken() != null) {
                dropboxSession = new WebAuthSession(appKeys, DROPBOX_ACCESS_TYPE, entry.getAccessToken());
            } else {
                dropboxSession = new WebAuthSession(appKeys, DROPBOX_ACCESS_TYPE);

                dropboxSession.retrieveWebAccessToken(new RequestTokenPair(entry.getKey(), entry.getsecret()));

                //Update the access token and re-save the cache entry
                entry.setAccessToken(dropboxSession.getAccessTokenPair());

                Cache.put(DROPBOX_CACHE_PREFIX + oauth_token, entry, DROPBOX_CACHE_EXPIRY);
            }

            DropboxAPI<WebAuthSession> api = new DropboxAPI<>(dropboxSession);

            String payload = null;

            Connection conn = BitcoinDatabaseManager.conn();
            try {
                PreparedStatement selectPayload = conn.prepareStatement("select payload from bitcoin_wallets where guid = ?");

                try {
                    selectPayload.setString(1, entry.getGuid());

                    ResultSet results = selectPayload.executeQuery();

                    if (results.next()) {
                        payload = results.getString(1);
                    } else {
                        throw new Exception("Unauthorized");
                    }

                } finally {
                    BitcoinDatabaseManager.close(selectPayload);
                }
            } finally {
                BitcoinDatabaseManager.close(conn);
            }

            if (payload != null && payload.length() > 0) {
                InputStream stream = new ByteArrayInputStream(payload.getBytes("UTF-8"));

                SimpleDateFormat format = new SimpleDateFormat("dd_MM_yyyy_HH_mm_ss");

                String dateString = format.format(new Date());

                api.putFile("wallet_"+dateString+".aes.json", stream, stream.available(), null, null);

                return true;
            } else {
                throw new Exception("Null payload");
            }
        } catch (Exception e) {
            return false;
        }
    }

    //Returns the total number of transactions and value
    public Pair<Long, Long> getMyWalletStats() throws SQLException {
        //Deep search every 60 minutes
        return Cache.getAndStore("my_wallet:stats2", 60, 172800, new BitcoinCache.CacheMiss(BitcoinDatabaseManager.mysql) {
            @Override
            public Object get(Connection conn) throws SQLException {
                PreparedStatement stmt = conn.prepareStatement("select count(*), SUM(value) from bitcoin_tx, bitcoin_tx_output where ipv4 = INET_ATON('127.0.0.1') and bitcoin_tx_output.tx_index = bitcoin_tx.tx_index");

                ResultSet results = stmt.executeQuery();
                if (results.next()) {
                    return new Pair<>(results.getLong(1), results.getLong(2));
                }

                return null;
            }});
    }

    public List<String> guidFromSMS(Connection conn, String sms) throws SQLException {
        List<String> data = new ArrayList<>();

        PreparedStatement select = conn.prepareStatement("select guid from bitcoin_wallets where sms_number = ? limit 4");
        try {
            select.setString(1, sms);

            ResultSet results = select.executeQuery();

            while(results.next()) {
                data.add(results.getString(1));
            }
        } finally {
            BitcoinDatabaseManager.close(select);
        }

        return data;
    }
    public List<String> guidFromEmail(Connection conn, String email) throws SQLException {
        List<String> data = new ArrayList<>();

        PreparedStatement select = conn.prepareStatement("select guid from bitcoin_wallets where email = ? limit 4");
        try {
            select.setString(1, email);

            ResultSet results = select.executeQuery();

            while(results.next()) {
                data.add(results.getString(1));
            }
        } finally {
            BitcoinDatabaseManager.close(select);
        }

        return data;
    }

    private void forwardToIndexPage(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {

        try {
            req.setAttribute("mywallet_stats", getMyWalletStats());
        } catch (SQLException e) {
            e.printStackTrace();
        }

        getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-index.jsp").forward(req, res);
    }

    private void forwardToAppPage(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        req.setAttribute("hide_language", true);

        getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-app.jsp").forward(req, res);
    }

    public boolean checkIsAuthorizedForWallet(HttpServletRequest req, HttpServletResponse res, WalletObject obj) {
        String saved_guid = (String) getSessionValue(req, res, SAVED_GUID_KEY);

        //Check to see if the user has their two factor authentication settings saved
        if (obj.auth_type == AuthTypeStandard) {

            //Clear the Saved GUID if it doesn't match this wallet
            if (saved_guid != null && !saved_guid.equals(obj.guid)) {
                deleteSessionValue(req, res, SAVED_GUID_KEY);
            }

            return true;
        } else if (obj.never_save_auth_type == 1) {
            return false;
        } else {
            Integer saved_auth_type = (Integer)getSessionValue(req, res, SAVED_AUTH_TYPE_KEY);

            if (saved_guid != null && saved_auth_type != null && saved_guid.equals(obj.guid) && saved_auth_type == obj.auth_type) {
                return true;
            }
        }

        return false;
    }

    @Override
    public boolean needsSecure() {
        return true;
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        try {
            super.doGet(req, res);
        } catch (ServletException e) {
            return;
        }

        req.setAttribute("no_search", true);
        req.setAttribute("show_adv", false);
        req.setAttribute("resource", LOCAL_RESOURCE_URL); //Never use static.blockchain.info
        req.setAttribute("no_footer", true);
        req.setAttribute("home_active", null);
        req.setAttribute("wallet_active", " class=\"active\"");
        req.setAttribute("dev_mode", devMode);

        req.setAttribute("LoggingLevelNone", LoggingLevelNone);
        req.setAttribute("LoggingLevelHashed", LoggingLevelHashed);
        req.setAttribute("LoggingLevelFull", LoggingLevelFull);

        req.setAttribute("NotificationsTypeEmail", NotificationsTypeEmail);
        req.setAttribute("NotificationsTypeGoogleTalk", NotificationsTypeGoogleTalk);
        req.setAttribute("NotificationsTypeHTTPPost", NotificationsTypeHTTPPost);
        req.setAttribute("NotificationsTypeSkype", NotificationsTypeSkype);
        req.setAttribute("NotificationsTypeTwitter", NotificationsTypeTwitter);
        req.setAttribute("NotificationsTypeSMS", NotificationsTypeSMS);
        req.setAttribute("NotificationsTypeBoxcar", NotificationsTypeBoxcar);

        req.setAttribute("show_disclaimer", false);

        req.setAttribute("enable_sms_deposit", Settings.instance().getBoolean("enable_sms_deposit"));
        req.setAttribute("enable_sofort_deposit", Settings.instance().getBoolean("enable_sofort_deposit"));
        req.setAttribute("enable_uk_bank_deposit", Settings.instance().getBoolean("enable_uk_bank_deposit"));
        req.setAttribute("enable_pingit_deposit", Settings.instance().getBoolean("enable_pingit_deposit"));
        req.setAttribute("enable_bitinstant_deposit", Settings.instance().getBoolean("enable_bitinstant_deposit"));

        req.setAttribute("enable_withdraw", Settings.instance().getBoolean("enable_withdraw"));
        req.setAttribute("enable_deposit", Settings.instance().getBoolean("enable_deposit"));
        req.setAttribute("enable_tweet_for_btc", Settings.instance().getBoolean("enable_tweet_for_btc"));

        req.setAttribute("enable_pingit_withdraw", Settings.instance().getBoolean("enable_pingit_withdraw"));
        req.setAttribute("enable_btcpak_withdraw", Settings.instance().getBoolean("enable_btcpak_withdraw"));

        req.setAttribute("enable_satoshidice", Settings.instance().getBoolean("enable_satoshidice"));
        req.setAttribute("enable_btcdice", Settings.instance().getBoolean("enable_btcdice"));

        req.setAttribute("help_link", Settings.instance().getString("help_link"));

        Language.Strings strings = getLanguage(req).getStrings();

        if (req.getPathInfo() == null || req.getPathInfo().length() == 0) {
            forwardToIndexPage(req, res);
            return;
        }

        String pathString = req.getPathInfo().substring(1);
        String components[] = pathString.split("/", -1);

        if (pathString == null || pathString.length() == 0 || components.length == 0) {
            forwardToIndexPage(req, res);
            return;
        }

        //Does not need to be escaped as it is never output
        String guid = components[0].trim();

        /** If no special cases were matched we actually display the wallet to the user from here on **/
        try {
            res.setHeader("Access-Control-Allow-Origin", "*");

            final String cguid = getCookieValue(req, TEMP_GUID_KEY);

            if (guid.equals("faq")) {
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-beginners-faq.jsp").forward(req, res);
                return;
            } else if (guid.equals("technical-faq")) {
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-technical-faq.jsp").forward(req, res);
                return;
            } else if (guid.equals("how-it-works")) {
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-how-it-works.jsp").forward(req, res);
                return;
            } else if (guid.equals("login") || guid.equals("claim"))  {

                String saved_guid = (String) getSessionValue(req, res, SAVED_GUID_KEY);

                if (saved_guid == null && cguid != null) {
                    saved_guid = cguid;
                }

                if (saved_guid != null && saved_guid.length() == 36 && !saved_guid.equals(DemoAccountGUID)) {
                    guid = saved_guid;
                } else {
                    req.setAttribute("guid", "");

                    forwardToAppPage(req, res);

                    return;
                }
            } else if (guid.equals("logout")) { //Special case for demo account - send users to signup page instead

                String saved_guid = (String) getSessionValue(req, res, SAVED_GUID_KEY);
                if (saved_guid != null) {
                    logAction(saved_guid, "logout", req.getRemoteAddr(), req.getHeader("User-Agent"));

                    deleteSessionValue(req, res, SAVED_GUID_KEY);
                    deleteSessionValue(req, res, SAVED_AUTH_TYPE_KEY);
                }

                res.sendRedirect(ROOT + "wallet");

            } else if (guid.equals("new")) { //Special case for demo account - send users to signup page instead
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-new.jsp").forward(req, res);
                return;
            } else if (guid.equals("paypal-vs-bitcoin")) {
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-vs-paypal.jsp").forward(req, res);
                return;
            } else if (guid.equals("android-app")) {
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-android.jsp").forward(req, res);
                return;
            }else if (guid.equals("translations")) {
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-translations.jsp").forward(req, res);
                return;
            } else if (guid.equals("iphone-app")) {
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-iphone.jsp").forward(req, res);
                return;
            } else if (guid.equals("sms-phone-deposits")) {
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-sms.jsp").forward(req, res);
                return;
            } else if (guid.equals("sms-two-factor")) {
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-sms-two-factor.jsp").forward(req, res);
                return;
            } else if (guid.equals("deposit-pingit")) {
                req.setAttribute("fee_percent", Settings.instance().getDouble("pingit_deposit_fee_percent"));
                req.setAttribute("minimum_deposit", Settings.instance().getDouble("pingit_deposit_minimum_order"));
                req.setAttribute("maximum_deposit", Settings.instance().getDouble("pingit_deposit_maximum_order"));
                req.setAttribute("weekly_limit", Settings.instance().getDouble("pingit_deposit_weekly_limit"));
                req.setAttribute("pingit_notice", Settings.instance().getString("pingit_notice"));
                req.setAttribute("pingit_mobile_number", Settings.instance().getString("pingit_mobile_number"));

                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-pingit.jsp").forward(req, res);
                return;
            } else if (guid.equals("deposit-sofort-banking")) {
                req.setAttribute("sofort_notice", Settings.instance().getString("sofort_notice"));
                req.setAttribute("fee_percent", Settings.instance().getDouble("sofort_deposit_fee_percent"));
                req.setAttribute("limits", Settings.instance().getMap("sofort_deposit_limits"));

                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-sofort.jsp").forward(req, res);
                return;
            } else if (guid.equals("deposit-bank-transfer")) {
                req.setAttribute("fee_percent", Settings.instance().getDouble("uk_bank_deposit_fee_percent"));
                req.setAttribute("minimum_deposit", Settings.instance().getDouble("uk_bank_deposit_minimum_order"));
                req.setAttribute("maximum_deposit", Settings.instance().getDouble("uk_bank_deposit_maximum_order"));
                req.setAttribute("weekly_limit", Settings.instance().getDouble("uk_bank_deposit_weekly_limit"));
                req.setAttribute("pingit_notice", Settings.instance().getString("uk_bank_notice"));

                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-uk-bank-transfer.jsp").forward(req, res);
                return;
            } else if (guid.equals("deposit-cash")) {
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-bitinstant.jsp").forward(req, res);
                return;
            } else if (guid.equals("send-via")) {
                try {
                    req.setAttribute("mywallet_stats", getMyWalletStats());
                } catch (SQLException e) {
                    e.printStackTrace();
                }

                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-send-via.jsp").forward(req, res);
                return;
            } else if (guid.equals("yubikey")) {
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-yubikey.jsp").forward(req, res);
                return;
            } else if (guid.equals("how-to-get-bitcoins")) {
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-how-to-get-bitcoins.jsp").forward(req, res);
                return;
            } else if (guid.equals("price-of-one-bitcoin")) {

                req.setAttribute("currencies", CurrencyManager.getSymbols());
                req.setAttribute("coin", BitcoinTx.COIN);

                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-price-of-a-bitcoin.jsp").forward(req, res);
                return;
            } else if (guid.equals("google-authenticator")) {
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-google-authenticator.jsp").forward(req, res);
                return;
            }else if (guid.equals("security")) {
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-security.jsp").forward(req, res);
                return;
            } else if (guid.equals("devices")) {
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-devices.jsp").forward(req, res);
                return;
            } else if (guid.equals("support-pages")) {
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-support.jsp").forward(req, res);
                return;
            }  else if (guid.equals("tweet-for-btc")) {
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-tweet-btc.jsp").forward(req, res);
                return;
            } else if (guid.equals("paper-tutorial")) {
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-paper-tutorial.jsp").forward(req, res);
                return;
            } else if (guid.equals("payment-notifications")) {
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-notifications.jsp").forward(req, res);
                return;
            } else if (guid.equals("backups")) {
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-backups.jsp").forward(req, res);
                return;
            } else if (guid.equals("anonymity")) {
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-anonymity.jsp").forward(req, res);
                return;
            } else if (guid.equals("send-anonymously")) {
                try {
                    req.setAttribute("mywallet_stats", getMyWalletStats());
                } catch (SQLException e) {
                    e.printStackTrace();
                }

                req.setAttribute("default_mixer_fee", ProcessForwardsOperation.getDefaultFee());
                req.setAttribute("max_bonus", ProcessForwardsOperation.getMaxBonus());
                req.setAttribute("mixer_fee", ProcessForwardsOperation.getCurrentFee());
                req.setAttribute("tx_fee", ProcessForwardsOperation.txFee());


                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-send-anonymously.jsp").forward(req, res);
                return;
            } else if (guid.equals("wallet-format")) {
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-format.jsp").forward(req, res);
                return;
            } else if (guid.equals("escrow")) {
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-escrow.jsp").forward(req, res);
                return;
            } else if (guid.equals("buy-one-bitcoin")) {
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-buy-one-bitcoin.jsp").forward(req, res);
                return;
            } else if (guid.equals("features")) {
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-features-list.jsp").forward(req, res);
                return;
            } else if (guid.equals("features")) {
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-features-list.jsp").forward(req, res);
                return;
            } else if (guid.equals("import-wallet")) {
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-import-wallet.jsp").forward(req, res);
                return;
            } else if (guid.equals("verifier")) {
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-verifier.jsp").forward(req, res);
                return;
            } else if (guid.equals("decryption-error")) {
                req.setAttribute("no_header", true);
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/mobile/bitcoin-wallet-decryption-error.jsp").forward(req, res);
                return;
            } else if (guid.equals("deposit-methods")) {
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/bitcoin-wallet-deposit-methods.jsp").forward(req, res);
                return;
            }else if (guid.equals("features")) {
                getServletContext().getRequestDispatcher("/WEB-INF/wallet/bitcoin-wallet-features-list.jsp").forward(req, res);
                return;
            }  else if (guid.equals("wallet.404.manifest")) {
                res.setStatus(404);
                return;
            } else if (guid.equals("wallet.manifest")) {
                addNoCacheHeaders(res);

                res.addHeader("Content-type", "text/cache-manifest");

                guid = req.getParameter("guid");

                if (guid != null) {
                    validateGUID(guid);

                    Connection conn = BitcoinDatabaseManager.conn();
                    try {
                        WalletObject obj = WalletObject.getWallet(conn, guid);

                        if (obj != null && obj.payload_checksum != null) {

                            if (obj.country != null) {
                                CurrencyManager.Symbol symbol = CurrencyManager.getSymbol(obj.country);
                                if (symbol != null)  {
                                    req.setAttribute("symbol_local", symbol.getCode());
                                }
                            }

                            if (obj.language != null) {
                                Language language = LanguageManager.getInstance().getLanguage(obj.language);
                                if (language != null)  {
                                    req.setAttribute("language_code", language.getCode());
                                }
                            }

                            if (obj.payload_checksum != null)
                                req.setAttribute("payload_checksum", new String(Hex.encode(obj.payload_checksum)));

                            if (obj.auth_type == AuthTypeStandard) {
                                getServletContext().getRequestDispatcher("/WEB-INF/wallet/bitcoin-wallet-manifest.jsp").forward(req, res);
                                return;
                            }
                        }
                    } finally {
                        BitcoinDatabaseManager.close(conn);
                    }
                }

                //If the auth type is not standard or the guid was not found return the 404 manifest
                res.setStatus(404);

                return;
            } else if (guid.equals("iphone-view")) {
                addNoCacheHeaders(res);

                req.setAttribute("no_header", true);

                String rguid = req.getParameter("guid");
                String sharedKey = req.getParameter("sharedKey");

                if (rguid == null || rguid.length() == 0 || sharedKey == null || sharedKey.length() == 0)
                    return;

                validateGUID(rguid);

                validateGUID(sharedKey);

                Connection conn = BitcoinDatabaseManager.conn();
                try {
                    PreparedStatement select_smt = conn.prepareStatement("select payload from bitcoin_wallets where guid = ? and shared_key = ?");

                    try {
                        select_smt.setString(1, rguid);
                        select_smt.setString(2, sharedKey);

                        ResultSet results = select_smt.executeQuery();

                        if (results.next()) {
                            logAction(rguid, "viewed iphone settings", req.getRemoteAddr(), req.getHeader("User-Agent"));

                            req.setAttribute("guid", rguid);
                            req.setAttribute("sharedKey", sharedKey);

                            getServletContext().getRequestDispatcher("/WEB-INF/wallet/mobile/bitcoin-wallet-mobile-index.jsp").forward(req, res);
                        } else {
                            req.setAttribute("initial_error", strings.getWallet_app().getErrors().getMobile_identifier_not_found());

                            getServletContext().getRequestDispatcher("/WEB-INF/wallet/mobile/bitcoin-wallet-mobile-not-found.jsp").forward(req, res);

                            return;
                        }
                    } finally {
                        BitcoinDatabaseManager.close(select_smt);
                    }
                } finally {
                    BitcoinDatabaseManager.close(conn);
                }

                return;
            } else if (guid.equals("get-backup")) {
                String rguid = req.getParameter("guid");
                String versionID = req.getParameter("id");
                String sharedKey = req.getParameter("sharedKey");

                validateGUID(rguid);

                validateGUID(sharedKey);

                Connection conn = BitcoinDatabaseManager.conn();
                try {
                    WalletObject obj = WalletObject.getWallet(conn, rguid);

                    if (obj == null)
                        throw new Exception(strings.getWallet_app().getErrors().getUnknown_identifier());

                    if (!obj.sharedKeyMatches(sharedKey))
                        throw new Exception(strings.getWallet_app().getErrors().getUnauthorized());

                } finally {
                    BitcoinDatabaseManager.close(conn);
                }

                logAction(rguid, "called get backup", req.getRemoteAddr(), req.getHeader("User-Agent"));

                if (versionID == null || versionID.length() == 0 || versionID.length() > 255)
                    throw new Exception(strings.getWallet_app().getErrors().getInvalid_version());

                String payload = S3.getWalletBackup(rguid, versionID);

                if (payload == null)
                    throw new Exception(strings.getWallet_app().getErrors().getWallet_identifier_not_found());

                res.setContentType("application/json");

                JSONObject obj = new JSONObject();

                obj.put("payload", payload);

                res.getWriter().print(obj.toJSONString());

                return;

            } else if (guid.equals("list-logs")) {
                String rguid = req.getParameter("guid");
                String sharedKey = req.getParameter("sharedKey");

                validateGUID(rguid);

                validateGUID(sharedKey);

                JSONObject container = new JSONObject();

                Connection conn = BitcoinDatabaseManager.conn();
                try {
                    WalletObject obj = WalletObject.getWallet(conn, rguid);

                    if (obj == null)
                        throw new Exception(strings.getWallet_app().getErrors().getUnknown_identifier());

                    if (!obj.sharedKeyMatches(sharedKey))
                        throw new Exception(strings.getWallet_app().getErrors().getUnauthorized());

                    PreparedStatement stmt = conn.prepareStatement("select message, time, ip, user_agent from bitcoin_wallet_actions where guid = ? order by time desc limit 1000");
                    try {
                        stmt.setString(1, rguid);

                        ResultSet results = stmt.executeQuery();

                        JSONArray array = new JSONArray();

                        while (results.next()) {
                            JSONObject json_obj = new JSONObject();

                            json_obj.put("action", StringEscapeUtils.escapeHtml(results.getString(1)));

                            json_obj.put("time", results.getLong(2));

                            String ipAddress = results.getString(3);

                            if (ipAddress != null && ipAddress.length() > 0) {
                                json_obj.put("ip_address", StringEscapeUtils.escapeHtml(ipAddress));
                            }else {
                                json_obj.put("ip_address", "Unknown");
                            }

                            String userAgent = results.getString(4);
                            if (userAgent != null && userAgent.length() > 0) {
                                json_obj.put("user_agent", StringEscapeUtils.escapeHtml(userAgent));
                            } else {
                                json_obj.put("user_agent", "Unknown");
                            }

                            array.put(json_obj);
                        }

                        container.put("results", array);
                    } finally {
                        BitcoinDatabaseManager.close(stmt);
                    }

                    res.setContentType("application/json");

                    res.getWriter().print(container.toJSONString());

                } finally {
                    BitcoinDatabaseManager.close(conn);
                }

                return;
            } else if (guid.equals("list-backups")) {

                String rguid = req.getParameter("guid");
                String sharedKey = req.getParameter("sharedKey");

                validateGUID(rguid);

                validateGUID(sharedKey);

                Connection conn = BitcoinDatabaseManager.conn();
                try {
                    WalletObject obj = WalletObject.getWallet(conn, rguid);

                    if (obj == null)
                        throw new Exception(strings.getWallet_app().getErrors().getUnknown_identifier());

                    if (!obj.sharedKeyMatches(sharedKey))
                        throw new Exception(strings.getWallet_app().getErrors().getUnauthorized());

                } finally {
                    BitcoinDatabaseManager.close(conn);
                }

                logAction(rguid, "called list backups", req.getRemoteAddr(), req.getHeader("User-Agent"));

                res.setContentType("application/json");

                addNoCacheHeaders(res);

                List<S3.BackupSummary> backups = S3.getWalletBackups(rguid);

                JSONObject container = new JSONObject();

                JSONArray array = new JSONArray();

                for (S3.BackupSummary backup : backups) {
                    JSONObject obj = new JSONObject();

                    obj.put("guid", backup.guid);
                    obj.put("name", backup.name);
                    obj.put("last_modified", backup.last_modified);
                    obj.put("size", backup.size);
                    obj.put("id", backup.id);

                    array.put(obj);
                }

                container.put("results", array);

                res.getWriter().print(container.toJSONString());

                return;
            } else if (guid.equals("forgot-identifier")) {
                addNoCacheHeaders(res);

                String param1 = req.getParameter("param1");

                if (param1 != null && param1.length() > 0) {
                    param1 = param1.trim();

                    List<String> guids = null;

                    if (!isValidEmailAddress(param1)) {
                        String phone = param1;

                        if (phone.charAt(0) != '+')
                            phone = '+' + phone;

                        Phonenumber.PhoneNumber number = PhoneNumberUtil.getInstance().parse(phone, "US");

                        int country_code = number.getCountryCode();

                        String formattedNumber = "+" + country_code + " " +number.getNationalNumber();

                        {
                            Connection conn = BitcoinDatabaseManager.conn();
                            try {
                                guids = guidFromSMS(conn, formattedNumber);
                            } finally {
                                BitcoinDatabaseManager.close(conn);
                            }
                        }

                        if (guids != null && guids.size() > 0) {
                            for (String email_guid : guids) {
                                logAction(email_guid, "called forget identifier", req.getRemoteAddr(), req.getHeader("User-Agent"));

                                Object recently_sent = Cache.get(email_guid+":forgot_recently_sent");

                                if (recently_sent == null) {
                                    SMS.sendSMS(email_guid, formattedNumber, "Link "+HTTPS_ROOT+"wallet/" + email_guid, SMS.HighPriority);

                                    Cache.put(email_guid+":forgot_recently_sent", true, 300);
                                }
                            }

                            req.setAttribute("initial_success",  strings.getWallet_app().getSuccess().getConfirmation_email_sent());
                        } else {
                            req.setAttribute("initial_error",  strings.getWallet_app().getErrors().getSms_not_found());
                        }
                    } else {
                        RequestLimiter.didRequest(req.getRemoteAddr(), 100); //Limited to approx 6 failed tries every 4 hours (Global over whole site)

                        Connection conn = BitcoinDatabaseManager.conn();
                        try {
                            guids = guidFromEmail(conn, param1);
                        } finally {
                            BitcoinDatabaseManager.close(conn);
                        }

                        if (guids != null && guids.size() > 0) {
                            for (String email_guid : guids) {
                                logAction(email_guid, "called forget identifier", req.getRemoteAddr(), req.getHeader("User-Agent"));

                                Object recently_sent = Cache.get(email_guid+":forgot_recently_sent");

                                if (recently_sent == null) {
                                    sendEmailLink(email_guid, false);
                                    Cache.put(email_guid+":forgot_recently_sent", true, 300);
                                }
                            }

                            req.setAttribute("initial_success",  strings.getWallet_app().getSuccess().getConfirmation_email_sent());
                        } else {
                            req.setAttribute("initial_error",  strings.getWallet_app().getErrors().getEmail_not_found());
                        }
                    }
                }

                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-forgot-identifier.jsp").forward(req, res);

                return;
            }  else if (guid.equals("password-hints")) {
                addNoCacheHeaders(res);

                String rguid = req.getParameter("guid");

                validateGUID(rguid);

                Connection conn = BitcoinDatabaseManager.conn();
                try {
                    WalletObject obj = WalletObject.getWallet(conn, rguid);

                    if (obj == null)
                        throw new Exception(strings.getWallet_app().getErrors().getWallet_identifier_not_found());

                    if (obj.password_hint1 == null || obj.password_hint1.length() == 0)
                        throw new Exception(strings.getWallet_app().getErrors().getPassword_hints_not_set());

                    if (obj.email_verified == 1 && obj.email != null) {
                        logAction(rguid, "password hints email sent", req.getRemoteAddr(), req.getHeader("User-Agent"));

                        if (sendPasswordHintsEmail(obj)) {
                            req.setAttribute("initial_success", strings.getWallet_app().getSuccess().getPassword_hints_sent());
                        } else {
                            req.setAttribute("initial_error", strings.getWallet_app().getErrors().getError_sending_password_hints());
                        }

                        forwardToAppPage(req, res);
                    } else {
                        logAction(rguid, "viewed password hints", req.getRemoteAddr(), req.getHeader("User-Agent"));

                        req.setAttribute("guid", obj.guid);

                        req.setAttribute("password_hint1", obj.password_hint1);

                        req.setAttribute("password_hint2", obj.password_hint2);

                        getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-password-hints.jsp").forward(req, res);
                    }
                } finally {
                    BitcoinDatabaseManager.close(conn);
                }
                return;
            } else if (guid.equals("reset-two-factor")) {
                try {
                    String rguid = req.getParameter("guid");

                    validateGUID(rguid);

                    req.setAttribute("guid", rguid);
                } catch (Exception e) { }

                getServletContext().getRequestDispatcher("/WEB-INF/wallet/"+ BaseServlet.ROOT + "bitcoin-wallet-reset-two-factor.jsp").forward(req, res);

                return;
            } else if (guid.equals("reset-two-factor-approve")) {
                addNoCacheHeaders(res);

                String email_code = req.getParameter("email_code");

                Connection conn = BitcoinDatabaseManager.conn();
                try {
                    //Set the new auth token
                    PreparedStatement update_smt = conn.prepareStatement("update reset_two_factor_requests set email_approved = 1 where email_code = ?");

                    try {
                        update_smt.setString(1, email_code);

                        update_smt.executeUpdate();

                        req.setAttribute("initial_success", strings.getWallet_app().getSuccess().getTwo_factor_authentication_request_approved());

                        forwardToIndexPage(req, res);

                        return;
                    } finally {
                        BitcoinDatabaseManager.close(update_smt);
                    }
                } finally {
                    BitcoinDatabaseManager.close(conn);
                }

            } else if (guid.equals("reset-two-factor-decline")) {
                addNoCacheHeaders(res);

                String email_code = req.getParameter("email_code");

                Connection conn = BitcoinDatabaseManager.conn();
                try {
                    //Set the new auth token
                    PreparedStatement update_smt = conn.prepareStatement("update reset_two_factor_requests set email_approved = -1 where email_code = ?");

                    try {
                        update_smt.setString(1, email_code);

                        update_smt.executeUpdate();

                        req.setAttribute("initial_error", strings.getWallet_app().getErrors().getTwo_factor_authentication_request_declined());

                        forwardToIndexPage(req, res);

                        return;
                    } finally {
                        BitcoinDatabaseManager.close(update_smt);
                    }
                } finally {
                    BitcoinDatabaseManager.close(conn);
                }

            } else if (guid.equals("dropbox-update")) {
                addNoCacheHeaders(res);

                String oauth_token = req.getParameter("oauth_token");

                if (doDropboxBackup(oauth_token)) {

                    res.getWriter().print(strings.getWallet_app().getSuccess().getSaved_to_dropbox());
                } else {
                    res.setStatus(500);
                    res.getWriter().print(strings.getWallet_app().getErrors().getError_saving_to_dropbox());
                }

                return;
            } else if (guid.equals("gdrive-update")) {
                addNoCacheHeaders(res);

                String rguid = (String)getSessionValue(req, res, "temp_guid");
                String token = req.getParameter("code");

                if (rguid == null){
                    throw new Exception(strings.getWallet_app().getErrors().getSession_expired());
                }

                validateGUID(rguid);

                Connection conn = BitcoinDatabaseManager.conn();
                try {
                    //Set the new auth token
                    PreparedStatement update_smt = conn.prepareStatement("update bitcoin_wallets set gdrive_auth_token = ? where guid = ?");

                    try {
                        update_smt.setString(1, token);
                        update_smt.setString(2, rguid);

                        update_smt.executeUpdate();
                    } finally {
                        BitcoinDatabaseManager.close(update_smt);
                    }
                }  finally {
                    BitcoinDatabaseManager.close(conn);
                }

                if (doGDriveBackup(rguid, token)) {
                    logAction(rguid, "updated google drive backup", req.getRemoteAddr(), req.getHeader("User-Agent"));

                    res.getWriter().print(strings.getWallet_app().getSuccess().getSaved_to_google_drive());
                } else {

                    res.setContentType("text/html");

                    res.getWriter().print("<h1>"+strings.getWallet_app().getErrors().getError_saving_to_google_drive()+"</h1> Be sure you have installed the <a href=\"https://chrome.google.com/webstore/detail/djjkppdfofjnpcbnkkangbhanjdnoocd\">My Wallet Chrome App</a> and blockchain.info is listed in your Google Drive Apps.");
                }

                return;
            } else if (guid.equals("gdrive-login")) {
                addNoCacheHeaders(res);

                String rguid = req.getParameter("guid");
                String sharedKey = req.getParameter("sharedKey");
                String auth_token = null;

                Connection conn = BitcoinDatabaseManager.conn();
                try {
                    //Read it back to double check
                    PreparedStatement select_smt = conn.prepareStatement("select gdrive_auth_token from bitcoin_wallets where guid = ? and shared_key = ?");

                    try {
                        select_smt.setString(1, rguid);
                        select_smt.setString(2, sharedKey);

                        ResultSet results = select_smt.executeQuery();

                        if (results.next()) {
                            auth_token = results.getString(1);
                        } else {
                            throw new Exception(strings.getWallet_app().getErrors().getUnauthorized());
                        }

                    } finally {
                        BitcoinDatabaseManager.close(select_smt);
                    }
                }  finally {
                    BitcoinDatabaseManager.close(conn);
                }

                if (auth_token != null) {
                    if (doGDriveBackup(rguid, auth_token)) {
                        res.getWriter().print(strings.getWallet_app().getSuccess().getSaved_to_google_drive());
                        return;
                    }
                }

                //Read when the user is sent back to the callback URL from google
                setSessionValue(req, res, "temp_guid", rguid, 3600);

                GoogleAuthorizationCodeRequestUrl urlBuilder =
                        new GoogleAuthorizationCodeRequestUrl(
                                GDRIVE_SECRETS.getWeb().getClientId(),
                                GDRIVE_SECRETS.getWeb().getRedirectUris().get(0),
                                GDRIVE_SCOPES)
                                .setAccessType("offline").setApprovalPrompt("force");

                String redirect_url = urlBuilder.build();

                res.sendRedirect(redirect_url);

                return;
            } else if (guid.equals("dropbox-login")) {
                addNoCacheHeaders(res);

                String rguid = req.getParameter("guid");
                String sharedKey = req.getParameter("sharedKey");
                String auth_token = null;

                {
                    Connection conn = BitcoinDatabaseManager.conn();
                    try {
                        //Read it back to double check
                        PreparedStatement select_smt = conn.prepareStatement("select dropbox_auth_token from bitcoin_wallets where guid = ? and shared_key = ?");

                        try {
                            select_smt.setString(1, rguid);
                            select_smt.setString(2, sharedKey);

                            ResultSet results = select_smt.executeQuery();

                            if (results.next()) {
                                auth_token = results.getString(1);
                            } else {
                                throw new Exception(strings.getWallet_app().getErrors().getUnauthorized());
                            }
                        } finally {
                            BitcoinDatabaseManager.close(select_smt);
                        }
                    }  finally {
                        BitcoinDatabaseManager.close(conn);
                    }
                }

                if (auth_token != null) {
                    if (doDropboxBackup(auth_token)) {
                        res.getWriter().print(strings.getWallet_app().getSuccess().getSaved_to_dropbox());
                        return;
                    }
                }

                AppKeyPair appKeys = new AppKeyPair(DROPBOX_APP_KEY, DROPBOX_APP_SECRET);

                WebAuthSession dropboxSession = new WebAuthSession(appKeys, DROPBOX_ACCESS_TYPE);

                WebAuthInfo authInfo = dropboxSession.getAuthInfo(DROPBOX_CALLBACK);

                if (authInfo != null) {

                    boolean didUpdate = false;
                    {
                        Connection conn = BitcoinDatabaseManager.conn();
                        try {
                            //Set the new auth token
                            PreparedStatement update_smt = conn.prepareStatement("update bitcoin_wallets set dropbox_auth_token = ? where guid = ? and shared_key = ?");

                            try {
                                update_smt.setString(1, authInfo.requestTokenPair.key);
                                update_smt.setString(2, rguid);
                                update_smt.setString(3, sharedKey);

                                //If successfull redirect the user to the oauth login page
                                if (update_smt.executeUpdate() == 1) {
                                    didUpdate = true;
                                }
                            } finally {
                                BitcoinDatabaseManager.close(update_smt);
                            }
                        }  finally {
                            BitcoinDatabaseManager.close(conn);
                        }
                    }

                    if (didUpdate) {
                        Cache.put(DROPBOX_CACHE_PREFIX + authInfo.requestTokenPair.key, new DropBoxCacheEntry(rguid, authInfo.requestTokenPair.key, authInfo.requestTokenPair.secret), DROPBOX_CACHE_EXPIRY);
                        res.sendRedirect(authInfo.url);
                    }
                } else {
                    throw new Exception(strings.getWallet_app().getErrors().getUnauthorized());
                }

                return;
            } else if (guid.equals("resolve-alias")) {
                addNoCacheHeaders(res);

                String rguid = req.getParameter("guid");
                {
                    Connection conn = BitcoinDatabaseManager.conn();
                    try {
                        PreparedStatement select_smt = conn.prepareStatement("select guid, shared_key from bitcoin_wallets where (guid = ? or alias = ?) and auth_type = 0");

                        try {
                            select_smt.setString(1, rguid);
                            select_smt.setString(2, rguid);

                            ResultSet results = select_smt.executeQuery();

                            if (results.next()) {
                                guid = results.getString(1);
                                String sharedKey = results.getString(2);

                                res.setContentType("application/json");

                                res.getWriter().print("{\"guid\" : \""+guid+"\", \"sharedKey\" : \"" + sharedKey + "\"}");
                            } else {

                                res.setStatus(500);

                                setPlainText(res);

                                res.getWriter().print(strings.getWallet_app().getErrors().getWallet_identifier_not_found());
                            }
                        } finally {
                            BitcoinDatabaseManager.close(select_smt);
                        }
                    }  finally {
                        BitcoinDatabaseManager.close(conn);
                    }
                }

                return;
            } else if (guid.equals("wallet.aes.json")) {
                addNoCacheHeaders(res);

                String rguid = req.getParameter("guid");
                String sharedKey = req.getParameter("sharedKey");
                String checksumString = req.getParameter("checksum");

                if (rguid == null || rguid.length() == 0 || sharedKey == null || sharedKey.length() == 0)
                    return;

                {
                    Connection conn = BitcoinDatabaseManager.conn();
                    try {

                        WalletObject obj = WalletObject.getWallet(conn, rguid);

                        if (obj != null) {
                            res.setContentType("application/octet-stream");

                            try {
                                if (!obj.sharedKeyMatches(sharedKey))
                                    throw new Exception(strings.getWallet_app().getErrors().getUnauthorized());

                                if (checksumString != null && obj.payload_checksum != null) {
                                    byte[] checksum = Hex.decode(checksumString);

                                    if (Arrays.equals(obj.payload_checksum, checksum)) {
                                        setSessionValue(req, res, SAVED_GUID_KEY, rguid, 86400);

                                        res.getWriter().print("Not modified");

                                        return;
                                    }
                                }
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        } else {
                            res.setStatus(500);

                            setPlainText(res);

                            res.getWriter().print(strings.getWallet_app().getErrors().getWallet_identifier_not_found());

                            return;
                        }

                        if (obj.payload != null)  {
                            if (!rguid.equals(DemoAccountGUID))
                                setSessionValue(req, res, SAVED_GUID_KEY, rguid, 86400);

                            res.getWriter().print(obj.payload);
                        } else {
                            res.setStatus(500);

                            setPlainText(res);

                            res.getWriter().print(strings.getWallet_app().getErrors().getPayload_null());
                            return;
                        }
                    }  finally {
                        BitcoinDatabaseManager.close(conn);
                    }
                }
                return;
            } else if (guid.equals("unsubscribe")) {
                String rguid = req.getParameter("guid");

                if (rguid == null || rguid.length() == 0)
                    return;


                {
                    Connection conn = BitcoinDatabaseManager.conn();
                    try {
                        String unscrambled = Scrambler.unscramble(rguid);

                        validateGUID(unscrambled);

                        logAction(rguid, "disable notifications", req.getRemoteAddr(), req.getHeader("User-Agent"));

                        PreparedStatement disable_notifications = conn.prepareStatement("update bitcoin_wallets set notifications_type = 0, notifications_disabled_until = ? where guid = ?");

                        try {
                            //Disable notifications for 24 hours
                            disable_notifications.setLong(1, System.currentTimeMillis() + 86400);

                            disable_notifications.setString(2, unscrambled);

                            if (disable_notifications.executeUpdate() == 1) {
                                req.setAttribute("initial_success", strings.getWallet_app().getSuccess().getUnsubscribed());
                            } else {
                                req.setAttribute("initial_error", strings.getWallet_app().getErrors().getError_unsubscribing());
                            }
                        } finally {
                            BitcoinDatabaseManager.close(disable_notifications);
                        }
                    }  finally {
                        BitcoinDatabaseManager.close(conn);
                    }
                }
                forwardToIndexPage(req, res);

                return;
            }

            WalletObject obj = null;
            {
                Connection conn = BitcoinDatabaseManager.conn();
                try {
                    //Guid might actually be an alias
                    obj = WalletObject.getWallet(conn, guid, guid);
                } finally {
                    BitcoinDatabaseManager.close(conn);
                }
            }

            //Should not be using it anymore
            guid = null;

            if (obj != null) {
                logAction(obj.guid, "viewed login page", req.getRemoteAddr(), req.getHeader("User-Agent"));

                if (obj.payload_checksum != null) {
                    String payload_checksum = new String(Hex.encode(obj.payload_checksum));
                    req.setAttribute("payload_checksum", payload_checksum);
                }

                if (obj.failed_logins >= MaxFailedLogins) {
                    if (lockAccount(obj, 240)) {
                        req.setAttribute("show_two_factor_reset", true);
                        throw new Exception(strings.getWallet_app().getErrors().getAccount_locked());
                    }
                } else if (obj.failed_logins > 0 && obj.auth_type != AuthTypeStandard) {
                    Format format = new Format();
                    format.setInput(strings.getWallet_app().getErrors().getLogin_attempts_left());
                    format.setParam1(""+(MaxFailedLogins - obj.failed_logins));

                    req.setAttribute("initial_error", format.formatString());
                }

                if (obj.ip_lock_on == 1 && obj.ip_lock != null && !obj.ip_lock.contains(req.getRemoteAddr())) {
                    logAction(obj.guid, "viewed login page wrong ip", req.getRemoteAddr(), req.getHeader("User-Agent"));

                    req.setAttribute("show_two_factor_reset", true);
                    throw new Exception(strings.getWallet_app().getErrors().getAccount_locked_to_another_ip());
                }

                long now = System.currentTimeMillis();

                if (obj.account_locked_time > now) {

                    logAction(obj.guid, "viewed login account locked", req.getRemoteAddr(), req.getHeader("User-Agent"));

                    Format format = new Format();
                    format.setInput(strings.getWallet_app().getErrors().getAccount_locked_for_minutes());
                    format.setParam1(""+((obj.account_locked_time - now) / 60000));

                    req.setAttribute("show_two_factor_reset", true);

                    throw new Exception(format.formatString());
                }

                //Special case for demo account
                if (obj.guid.equals(DemoAccountGUID)) {
                    req.setAttribute("demo", true);
                } else {
                    Cache.put(req.getRemoteAddr() + "ip_guid", obj.guid, 3600);

                    if (obj.country != null) {
                        //Save the currency
                        CurrencyManager.Symbol symbol = CurrencyManager.getSymbol(obj.country);
                        if (symbol != null)  {
                            req.setAttribute("symbol_local", symbol);
                        }
                    }

                    if (obj.language != null) {
                        Language language = LanguageManager.getInstance().getLanguage(obj.language);
                        if (language != null) {

                            setLanguage(req, res, language);
                        }
                    }
                }

                req.setAttribute("guid", obj.guid);

                if (!obj.guid.equals(DemoAccountGUID) && (cguid == null || !cguid.equals(obj.guid))) {
                    putCookie(req, res, TEMP_GUID_KEY, obj.guid);
                }

                req.setAttribute("auth_type", obj.auth_type);
                req.setAttribute("show_logout", true);

                //Check to see if the user has their two factor authentication settings saved
                if (checkIsAuthorizedForWallet(req, res, obj)) {
                    req.setAttribute("wallet_data", obj.payload);
                } else { //Otherwise we need them to authorize themselves

                    //If email code is null or it's older than one hour resend it
                    //Or the user has mnaually requested a new code
                    final boolean manual = req.getParameter("resend_code") != null && req.getParameter("resend_code").equals("true");

                    if (obj.auth_type == AuthTypeYubikey ||  obj.auth_type == AuthTypeYubikeyMtGox) {
                        //Check that the user has as entered a yubikey in a valid format (in case they didn't fill out the form correctly)
                        if (obj.yubikey == null || obj.yubikey.length() == 0) {
                            req.setAttribute("auth_type", AuthTypeStandard);
                            req.setAttribute("wallet_data", obj.payload);
                        } else {
                            req.setAttribute("show_yubikey", true);
                        }
                    } else if (obj.auth_type == AuthTypeGoogleAuthenticator) {
                        req.setAttribute("show_google_auth", true);
                    } else if (obj.auth_type == AuthTypeSMS) {
                        if (obj.sms_verified == 1 && obj.sms_number != null) {
                            req.setAttribute("show_sms", true);
                            req.setAttribute("auth_type", AuthTypeSMS);

                            if (obj.sms_code == null || manual || obj.sms_code.length() == 0 || obj.sms_code_last_updated < System.currentTimeMillis() - (14400000)) {

                                String code = null;

                                Connection conn = BitcoinDatabaseManager.conn();
                                try {
                                    code = generateAndUpdateSMSCode(conn, obj.guid);
                                } finally {
                                    BitcoinDatabaseManager.close(conn);
                                }

                                Format format = new Format();

                                format.setInput(strings.getNotifications().getSms_authentication_code());

                                format.setParam1(code);

                                if (SMS.sendSMS(obj.guid, obj.sms_number, format.formatString(), SMS.MediumPriority)) {
                                    req.setAttribute("initial_success", strings.getWallet_app().getSuccess().getSms_code_sent());
                                } else {
                                    req.setAttribute("initial_error", strings.getWallet_app().getErrors().getError_sending_sms_code());

                                    req.setAttribute("auth_type", AuthTypeStandard);
                                    req.setAttribute("wallet_data", obj.payload);

                                    clearAuthCodes(obj.guid);
                                }
                            }
                        } else {
                            req.setAttribute("auth_type", AuthTypeStandard);
                            req.setAttribute("wallet_data", obj.payload);
                        }
                    } else if (obj.auth_type == AuthTypeEmail) {
                        if (obj.email == null || obj.email.length() == 0) {
                            req.setAttribute("initial_error", strings.getWallet_app().getErrors().getTwo_factor_enabled_no_email());

                            req.setAttribute("auth_type", AuthTypeStandard);
                            req.setAttribute("wallet_data", obj.payload);

                        } else if (obj.email_verified == 0) {
                            req.setAttribute("initial_error", strings.getWallet_app().getErrors().getTwo_factor_enabled_email_not_verified());

                            req.setAttribute("auth_type", AuthTypeStandard);
                            req.setAttribute("wallet_data", obj.payload);
                        } else {
                            req.setAttribute("show_email", true);

                            if (obj.email_code == null || obj.email_code.length() == 0 || obj.email_code_last_updated < System.currentTimeMillis() - 600000 || manual) {
                                if (obj.emails_today > MaxEmailsInOneDay) {

                                    Format format = new Format();
                                    format.setInput(strings.getWallet_app().getErrors().getReached_email_limit());
                                    format.setParam1(""+MaxEmailsInOneDay);

                                    req.setAttribute("initial_error", format.formatString());
                                } else {
                                    String code = null;
                                    {
                                        Connection conn = BitcoinDatabaseManager.conn();
                                        try {
                                            code = generateAndUpdateEmailCode(conn, obj.guid);
                                        } finally {
                                            BitcoinDatabaseManager.close(conn);
                                        }
                                    }
                                    if (code != null) {
                                        if (sendTwoFactorEmail(obj, code, req.getRemoteAddr())) {
                                            {
                                                Connection conn = BitcoinDatabaseManager.conn();
                                                try {
                                                    if (manual) {
                                                        incrementFailedLogins(conn, obj.guid);
                                                        req.setAttribute("initial_success", strings.getWallet_app().getSuccess().getEmail_code_resent());
                                                    } else {
                                                        req.setAttribute("initial_success", strings.getWallet_app().getSuccess().getEmail_code_sent());
                                                    }

                                                    incrementEmailCount(conn, guid);
                                                } finally {
                                                    BitcoinDatabaseManager.close(conn);
                                                }
                                            }
                                        } else {
                                            req.setAttribute("initial_error", strings.getWallet_app().getErrors().getError_sending_two_factor_email());

                                            req.setAttribute("auth_type", AuthTypeStandard);
                                            req.setAttribute("wallet_data", obj.payload);

                                            clearAuthCodes(obj.guid);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                forwardToAppPage(req, res);
            } else {
                if (!res.isCommitted()) {
                    res.setStatus(500);

                    RequestLimiter.didRequest(req.getRemoteAddr(), 50); //Limited to approx 6 failed tries every 4 hours (Global over whole site)

                    req.setAttribute("guid", "");

                    req.setAttribute("initial_error", strings.getWallet_app().getErrors().getUnknown_identifier());

                    forwardToAppPage(req, res);
                }

                return;
            }

        } catch (Exception e) {

            RequestLimiter.didRequest(req.getRemoteAddr(), 50);

            e.printStackTrace();

            printHTTP(req);

            if (req.getParameter("format") == null) {

                req.setAttribute("initial_error", e.getLocalizedMessage());

                forwardToIndexPage(req, res);

            } else if (req.getParameter("format").equals("plain")) {
                res.setStatus(500);

                setPlainText(res);

                if (e.getLocalizedMessage() != null)
                    res.getWriter().print(StringEscapeUtils.escapeXml(e.getLocalizedMessage()));
                else
                    res.getWriter().print(strings.getMisc().getUnknown_exception());
            }
        }
    }

    public void clearAuthCodes(String guid) throws SQLException {
        PreparedStatement update_succees = null;
        Connection conn = BitcoinDatabaseManager.conn();
        try {
            //Reset the email code because it's possible the confirmation email got lost somewhere on the intertubes
            update_succees = conn.prepareStatement("update bitcoin_wallets set sms_code = NULL,  email_code = NULL, failed_logins = 0, last_two_factor_login = ? where guid = ?");

            update_succees.setLong(1, System.currentTimeMillis());
            update_succees.setString(2, guid);

            update_succees.executeUpdate();
        } finally {
            BitcoinDatabaseManager.close(update_succees);
            BitcoinDatabaseManager.close(conn);
        }
    }
    public static boolean lockAccount(WalletObject obj, int minutes) {
        long lock_time =  System.currentTimeMillis() + (minutes * 60000);

        if (obj.email != null) {
            Map<String, String> params = new HashMap<>();

            params.put("date", new Date(lock_time).toString());

            try {
                String template = EmailTemplate.getTemplate(obj.guid, "wallet-locked", obj.language, params);

                NotificationsManager.sendMail(obj.email, obj.getLanguage().getStrings().getNotifications().getAccount_locked_title(), template);

            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        Connection conn = BitcoinDatabaseManager.conn();
        PreparedStatement smt = null;
        try {
            //Reset the email code because it's possible the confirmation email got lost somewhere on the intertubes
            smt = conn.prepareStatement("update bitcoin_wallets set acount_locked_time = ?, failed_logins = 0, sms_code = null, email_code = null  where guid = ?");

            smt.setLong(1, lock_time);
            smt.setString(2, obj.guid);

            smt.executeUpdate();

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            BitcoinDatabaseManager.close(smt);
            BitcoinDatabaseManager.close(conn);
        }

        return true;
    }

    public static boolean sendPasswordHintsEmail(WalletObject obj) throws Exception {

        Connection conn = BitcoinDatabaseManager.conn();
        try {

            String template = EmailTemplate.getTemplate(obj.guid, "password-hints", obj.language);

            if (template != null) {
                NotificationsManager.sendMail(obj.email, obj.getLanguage().getStrings().getNotifications().getPassword_hints_title(), template);
                try {
                    incrementEmailCount(conn, obj.guid);
                } catch (SQLException e) {
                    e.printStackTrace();
                }

                return true;
            }

            return false;
        } finally {
            BitcoinDatabaseManager.close(conn);
        }
    }

    public static boolean sendEmailLink(String guid, boolean attachBackup) {

        WalletObject obj = null;
        {
            Connection conn = BitcoinDatabaseManager.conn();
            try {
                obj = WalletObject.getWallet(conn, guid);
            } catch (Exception e) {
                e.printStackTrace();

                return false;
            } finally {
                BitcoinDatabaseManager.close(conn);
            }
        }

        String template;

        try {
            template = EmailTemplate.getTemplate(obj.guid, "welcome", obj.language);
        } catch (Exception e) {
            e.printStackTrace();

            return false;
        }

        if (template != null && obj.email != null && obj.emails_today < MaxEmailsInOneDay) {

            if (attachBackup)
                NotificationsManager.sendMail(obj.email, obj.getLanguage().getStrings().getNotifications().getWallet_welcome_title(), template, AdminServlet.getLocalServerRoot()+"wallet/wallet.aes.json?guid="+guid+"&sharedKey="+obj.shared_key);
            else
                NotificationsManager.sendMail(obj.email, obj.getLanguage().getStrings().getNotifications().getWallet_welcome_title(), template);

            {
                Connection conn = BitcoinDatabaseManager.conn();

                try {
                    incrementEmailCount(conn, guid);
                } catch (SQLException e) {
                    e.printStackTrace();
                }  finally {
                    BitcoinDatabaseManager.close(conn);
                }
            }

            return true;
        }

        return false;
    }

    public static String generateAndUpdateSMSCode(Connection conn, String guid) throws SQLException {
        String code = UUID.randomUUID().toString().substring(0, SMSCodeLength).toUpperCase();

        //Reset the email code because it's possible the confirmation email got lost somewhere on the intertubes
        PreparedStatement smt = conn.prepareStatement("update bitcoin_wallets set sms_code = ?, sms_code_last_updated = ? where guid = ?");
        try {
            smt.setString(1, code);
            smt.setLong(2, System.currentTimeMillis());
            smt.setString(3, guid);

            if (smt.executeUpdate() == 1)
                return code;

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            BitcoinDatabaseManager.close(smt);
        }

        return null;
    }

    public static String generateAndUpdateEmailCode(Connection conn, String guid) throws SQLException {
        String code = UUID.randomUUID().toString().substring(0, EmailCodeLength).toUpperCase();

        //Reset the email code because it's possible the confirmation email got lost somewhere on the intertubes
        PreparedStatement smt = conn.prepareStatement("update bitcoin_wallets set email_code = ?, email_code_last_updated = ? where guid = ?");
        try {
            smt.setString(1, code);
            smt.setLong(2, System.currentTimeMillis());
            smt.setString(3, guid);

            if (smt.executeUpdate() == 1)
                return code;

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            BitcoinDatabaseManager.close(smt);
        }

        return null;
    }

    public void incrementFailedLogins(Connection conn, String guid) throws SQLException {
        PreparedStatement update_logins = null;
        try {
            update_logins = conn.prepareStatement("update bitcoin_wallets set failed_logins = failed_logins + 1 where guid = ?");

            update_logins.setString(1, guid);

            update_logins.executeUpdate();
        } finally {
            BitcoinDatabaseManager.close(update_logins);
        }
    }

    public static boolean sendTwoFactorEmail(WalletObject obj, String code, String ip) throws Exception {

        Map<String, String> params = new HashMap<>();

        params.put("ip", ip);

        params.put("code", code);

        String template = EmailTemplate.getTemplate(obj.guid, "confirmation-code", obj.language, params);

        return NotificationsManager.sendMail(obj.email, obj.getLanguage().getStrings().getNotifications().getConfirmation_code_title(), template);
    }

    public static void logAdminAction(final String guid, final String message) {

        GlobalExecutorService.ex.execute(new Runnable() {
            public void run() {
                Connection conn = BitcoinDatabaseManager.conn();
                try {
                    PreparedStatement smt = conn.prepareStatement("insert into bitcoin_wallet_actions (guid, message, time) values (?, ?, ?)");
                    try {
                        smt.setString(1, guid);
                        smt.setString(2, message);
                        smt.setLong(3, System.currentTimeMillis());

                        smt.executeUpdate();

                    } finally {
                        BitcoinDatabaseManager.close(smt);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    BitcoinDatabaseManager.close(conn);
                }
            }
        });
    }

    public static void logAction(final String guid, final String message, final String _ip, final String _userAgent) {

        GlobalExecutorService.ex.execute(new Runnable() {
            public void run() {
                Connection conn = BitcoinDatabaseManager.conn();
                try {
                    String ip = _ip;
                    String userAgent = _userAgent;

                    int logging_level;

                    {
                        PreparedStatement smt = conn.prepareStatement("select logging_level from bitcoin_wallets where guid = ?");
                        try {
                            smt.setString(1, guid);

                            ResultSet results = smt.executeQuery();

                            if (results.next()) {
                                logging_level = results.getInt(1);
                            } else {
                                return;
                            }
                        } finally {
                            BitcoinDatabaseManager.close(smt);
                        }
                    }

                    if (logging_level == LoggingLevelNone) {
                        return;
                    }

                    if (logging_level == LoggingLevelHashed) {
                        ip = Util.SHA256Hex(ip);
                        userAgent = null;
                    }

                    if (userAgent != null && userAgent.length() > 512)
                        userAgent = userAgent.substring(0, Math.min(userAgent.length(), 512));

                    PreparedStatement smt = conn.prepareStatement("insert into bitcoin_wallet_actions (guid, message, time, ip, user_agent) values (?, ?, ?, ?, ?)");
                    try {
                        smt.setString(1, guid);
                        smt.setString(2, message);
                        smt.setLong(3, System.currentTimeMillis());
                        smt.setString(4, ip);
                        smt.setString(5, userAgent);

                        smt.executeUpdate();

                    } finally {
                        BitcoinDatabaseManager.close(smt);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    BitcoinDatabaseManager.close(conn);
                }
            }
        });
    }

    private static void incrementEmailCount(Connection conn, String guid) throws SQLException {
        PreparedStatement update_backup_count = null;

        try {
            update_backup_count =  conn.prepareStatement("update bitcoin_wallets set email_backups_today = email_backups_today+1 where guid = ?");

            update_backup_count.setString(1, guid);

            update_backup_count.executeUpdate();

        } finally {
            BitcoinDatabaseManager.close(update_backup_count);
        }
    }

    public static boolean sendEmailBackup(WalletObject obj) throws Exception {

        String template = EmailTemplate.getTemplate(obj.guid, "backup-email", obj.language);

        try {
            return NotificationsManager.sendMail(obj.email, obj.getLanguage().getStrings().getNotifications().getWallet_backup_title(), template, AdminServlet.getLocalServerRoot()+"wallet/wallet.aes.json?guid="+obj.guid+"&sharedKey="+obj.shared_key);
        } finally {
            Connection conn = BitcoinDatabaseManager.conn();
            try {
                incrementEmailCount(conn, obj.guid);
            } finally {
                BitcoinDatabaseManager.close(conn);
            }
        }
    }

    public static boolean isValidEmailAddress(String aEmailAddress){
        try {
            InternetAddress emailAddr = new InternetAddress(aEmailAddress);

            emailAddr.validate();

            return true;
        } catch (Exception ex){
            return false;
        }
    }

    public static boolean backupWallet(WalletObject obj) throws Exception {
        boolean done_backup = false;

        //If the user has a dropbox session do an automatic backup
        if (!done_backup && obj.gdrive_auth_token != null) {
            done_backup = doGDriveBackup(obj.guid, obj.gdrive_auth_token);
        }

        //If the user has a dropbox session do an automatic backup
        if (!done_backup && obj.dropbox_auth_token != null) {
            done_backup = doDropboxBackup(obj.dropbox_auth_token);
        }

        //Do an automatic email backup
        if (!done_backup && obj.auto_email_backup == 1 && obj.email_verified == 1 && obj.emails_today <= MaxBackupsInOneDay) {
            done_backup = sendEmailBackup(obj);
        }

        return done_backup;
    }

    public static void fixSMSNumbers(Connection conn) throws SQLException, NoSuchAlgorithmException, UnsupportedEncodingException {

        PreparedStatement select_smt = conn.prepareStatement("select sms_number, guid from bitcoin_wallets where sms_number is not null");
        PreparedStatement update_smt = conn.prepareStatement("update bitcoin_wallets set sms_number = ? where guid = ?");

        try {
            ResultSet results = select_smt.executeQuery();

            while (results.next()) {

                String sms_number = results.getString(1);
                try {
                    sms_number = sms_number.replace("null", "");

                    Phonenumber.PhoneNumber number = PhoneNumberUtil.getInstance().parse(sms_number, "US");

                    int country_code = number.getCountryCode();

                    String formattedNumber = "+" + country_code + " " +number.getNationalNumber();

                    update_smt.setString(1, formattedNumber);
                    update_smt.setString(2, results.getString(2));

                    System.out.println("Reformat SMS Number " + sms_number + " as " + formattedNumber);

                    update_smt.executeUpdate();
                } catch (Exception e ) {

                    System.out.println("Error " + sms_number);
                    e.printStackTrace();
                }
            }

        } finally {
            BitcoinDatabaseManager.close(select_smt);
            BitcoinDatabaseManager.close(update_smt);
        }
    }

    public boolean validateAlias(String alias) {
        if (alias == null || alias.length() == 0 || alias.length() >= 255)
            return false;

        if (StringUtils.containsAny(alias, "!@€#£¢$∞%§^¶•*ªº()=±[]{}:;'\"|«æ…“‘\\/><≥≤`~%")) {
            return false;
        }

        return true;
    }

    public static void verifyAllWalletChecksums(Connection conn) throws SQLException, NoSuchAlgorithmException, UnsupportedEncodingException {


        int total = 0;
        List<String> bad_guids = new ArrayList<>();

        PreparedStatement select_smt = conn.prepareStatement("select guid, payload, payload_checksum from bitcoin_wallets where payload_checksum is not null");
        try {
            ResultSet results = select_smt.executeQuery();

            while (results.next()) {
                String guid = results.getString(1);
                String wallet_payload = results.getString(2);
                byte[] payload_checksum = results.getBytes(3);
                byte[] thedigest = Util.SHA256(wallet_payload).getBytes();

                if (!Base64.isBase64(wallet_payload) || !Arrays.equals(thedigest, payload_checksum)) {
                    bad_guids.add(guid);
                }

                ++total;
            }

            System.out.println("Checked " + total + " wallets " + bad_guids.size() + " currupted");

            if (bad_guids.size() > 0)
                System.out.println("Basd GUIDs " + bad_guids);
        } finally {
            BitcoinDatabaseManager.close(select_smt);
        }
    }

    public static class InvalidGUIDException extends IllegalArgumentException {
        public InvalidGUIDException(String guid) {
            super("Invalid GUID");

            System.out.println("InvalidGUIDException " + guid);
        }
    }

    public static void validateGUID(String input_guid) throws IllegalArgumentException {
        if (input_guid == null)
            throw new InvalidGUIDException(input_guid);

        String guid = input_guid.trim();

        if (guid.length() != 36)
            throw new InvalidGUIDException(input_guid);

        //All commands must have a guid
        int pre_guid_length = input_guid.length();

        guid = Jsoup.parse(input_guid).text(); //Strip and html

        try {
            guid = UUID.fromString(guid).toString(); //Check is valid uuid format
        } catch (IllegalArgumentException e) {
            throw new InvalidGUIDException(input_guid);
        }

        //Change to see if we stripped anything - could be a sign of malicious input
        if (guid.length() != 36 || pre_guid_length != guid.length()) {
            throw new InvalidGUIDException(input_guid);
        }
    }

    public static boolean aliasIsInUse(Connection conn, String alias) throws SQLException {
        PreparedStatement smt = conn.prepareStatement("select count(*) from bitcoin_wallets where alias = ?");
        try {
            smt.setString(1, alias);

            ResultSet results = smt.executeQuery();

            if (results.next()) {
                if (results.getInt(1) > 0) {
                    return true;
                }
            }
        } finally {
            BitcoinDatabaseManager.close(smt);
        }

        return false;
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        try {
            super.doPost(req, res);
        } catch (ServletException e) {
            return;
        }

        Language.Strings strings = getLanguage(req).getStrings();

        setPlainText(res);

        try {
            final String guid = req.getParameter("guid");
            String sharedKey = req.getParameter("sharedKey");
            String payload = req.getParameter("payload");
            String method = req.getParameter("method");
            String length = req.getParameter("length");

            validateGUID(guid);

            //get-info has no payload
            if (!method.equals("get-info") && !method.equals("email-backup") && !method.equals("reset-two-factor")) {
                int pre_payload_length = payload.length();

                //Strip and html or javascript
                payload = Jsoup.parse(payload).text();

                int ulength = 0;
                try {
                    ulength = Integer.valueOf(length).intValue(); //Must catch this as potential for XSS here
                } catch (Exception e) {
                    throw new Exception(strings.getWallet_app().getErrors().getInvalid_length());
                }

                //Check length to see if we stripped anything - could be a sign of malicious input
                //Length verification also serves as rudimentary data corruption check
                //Wallet payload is properly verified with a checksum later
                if (payload == null || payload.length() == 0  || pre_payload_length != payload.length() || ulength!= payload.length()) {
                    System.out.println("Wallet POST Payload : " + payload + " is invalid " + method + " payload length " + payload.length() + " pre payload length " + pre_payload_length);

                    throw new Exception(strings.getWallet_app().getErrors().getInvalid_payload());
                }
            }

            //Shared key is not needed for the get-wallet method
            if (!method.equals("get-wallet") && !method.equals("reset-two-factor")) {
                try {
                    validateGUID(sharedKey);
                } catch (Exception e) {
                    System.out.println("Invalid Shared Key " + sharedKey);
                    throw e;
                }
            }


            long now = new Date().getTime();

            //Special case for demo account, don't allow modifications
            if (guid.equals(DemoAccountGUID) && !method.equals("get-info")) {
                res.getWriter().print(strings.getWallet_app().getSuccess().getSuccess());
                return;
            }

            if (method.equals("insert")) {
                String kaptchaExpected = (String)getSessionValue(req, res, com.google.code.kaptcha.Constants.KAPTCHA_SESSION_KEY);
                String kaptchaReceived = req.getParameter("kaptcha");

                if (kaptchaReceived == null || !kaptchaReceived.equalsIgnoreCase(kaptchaExpected))
                {
                    res.setStatus(500);
                    res.getWriter().print(strings.getWallet_app().getErrors().getCaptcha_incorrect());
                    return;
                }

                if (!Base64.isBase64(payload)) {
                    throw new Exception(strings.getWallet_app().getErrors().getInvalid_payload());
                }

                if (payload.length() > 1048576) {
                    throw new Exception(strings.getWallet_app().getErrors().getWallet_size_restricted());
                }

                String alias = req.getParameter("alias");
                if (alias != null) {
                    alias = alias.trim();

                    if (alias.length() == 0) {
                        alias = null;
                    } else {
                        if (!validateAlias(alias)) {
                            throw new Exception(strings.getWallet_app().getErrors().getInvalid_alias());
                        }

                        Connection conn = BitcoinDatabaseManager.conn();

                        try {
                            if (aliasIsInUse(conn, alias)) {
                                throw new UnprintableException(strings.getWallet_app().getErrors().getError_alias_taken());
                            }
                        } finally {
                            BitcoinDatabaseManager.close(conn);
                        }
                    }
                }

                String hashed_ip = Util.SHA256Hex(req.getRemoteAddr());

                //Get the Users current language
                Language language = getLanguage(req);

                //Get the Users local currency
                CurrencyManager.Symbol symbol = getLocalSymbol(req);

                final byte[] checksum = Util.SHA256(payload).getBytes();

                PreparedStatement smt = null;
                Connection conn = BitcoinDatabaseManager.conn();
                try {
                    smt = conn.prepareStatement("insert into bitcoin_wallets (guid, created, payload, shared_key, created_ip, payload_checksum, country, language, alias) values(?, ?, ?, ?, ?, ?, ?, ?, ?)");

                    smt.setString(1, guid);
                    smt.setLong(2, now);
                    smt.setString(3, payload);
                    smt.setString(4, sharedKey);
                    smt.setString(5, hashed_ip);
                    smt.setBytes(6, checksum);
                    smt.setString(7, symbol.getCode());
                    smt.setString(8, language.getCode());
                    smt.setString(9, alias);

                    if (smt.executeUpdate() == 1) {
                        putCookie(req, res, TEMP_GUID_KEY, guid);

                        //Update in background
                        final String finalPayload = payload;
                        GlobalExecutorService.ex.execute(new Runnable() {
                            public void run() {
                                try {
                                    //Save To S3
                                    S3.saveWallet(guid, finalPayload, checksum);
                                } catch (Throwable e) {
                                    e.printStackTrace();
                                }
                            }
                        });

                        logAction(guid, "insert wallet", req.getRemoteAddr(), req.getHeader("User-Agent"));

                        res.getWriter().print(strings.getWallet_app().getSuccess().getCreate_wallet_success());
                    } else {
                        res.setStatus(500);
                        res.getWriter().print(strings.getWallet_app().getErrors().getError_saving_wallet());
                    }
                } finally {
                    BitcoinDatabaseManager.close(smt);
                    BitcoinDatabaseManager.close(conn);
                }

            } else if (method.equals("update")) {
                if (!Base64.isBase64(payload)) {
                    logAction(guid, "update wallet invalid payload", req.getRemoteAddr(), req.getHeader("User-Agent"));

                    throw new Exception(strings.getWallet_app().getErrors().getInvalid_payload());
                }

                if (payload.length() > 1048576) {
                    logAction(guid, "update wallet payload too long", req.getRemoteAddr(), req.getHeader("User-Agent"));

                    throw new Exception(strings.getWallet_app().getErrors().getWallet_size_restricted());
                }

                final String checksumString =  req.getParameter("checksum");

                byte[] checksum = Hex.decode(checksumString);

                byte[] thedigest = Util.SHA256(payload).getBytes();

                if (!Arrays.equals(thedigest, checksum)) {
                    logAction(guid, "update wallet checksum invalid", req.getRemoteAddr(), req.getHeader("User-Agent"));

                    throw new Exception(strings.getWallet_app().getErrors().getChecksum_invalid());
                }

                //User supplies the checksum of the old wallet they had before the update
                //So we can check that they haven't updated the wallet with another device and are overwriting any changes
                String old_checksum = req.getParameter("old_checksum");
                byte[] old_checksum_bytes = null;
                if (old_checksum != null && old_checksum.length() > 0) {
                    old_checksum_bytes = Hex.decode(old_checksum);
                }

                String hashed_ip = Util.SHA256Hex(req.getRemoteAddr());

                //Retry up to 3 times due to MySQL Cluster deadlock errors
                boolean didInsert = false;
                for (int ii = 0; ii < 3; ++ii) {
                    try {
                        Connection conn = BitcoinDatabaseManager.conn();
                        PreparedStatement update_smt = null;
                        try {
                            String sql = "update bitcoin_wallets set payload = ?, updated = ?, updated_ip = ?, payload_checksum = ? where guid = ? and shared_key = ?";

                            if (old_checksum_bytes != null)
                                sql += "  and (payload_checksum is null or payload_checksum = ?)";

                            update_smt = conn.prepareStatement(sql);
                            update_smt.setString(1, payload);
                            update_smt.setLong(2, now);
                            update_smt.setString(3, hashed_ip);
                            update_smt.setBytes(4, checksum);
                            update_smt.setString(5, guid);
                            update_smt.setString(6, sharedKey);

                            if (old_checksum_bytes != null)
                                update_smt.setBytes(7, old_checksum_bytes);

                            if (update_smt.executeUpdate() == 1) {
                                didInsert = true;
                            }

                            break;
                        } finally {
                            BitcoinDatabaseManager.close(update_smt);
                            BitcoinDatabaseManager.close(conn);
                        }
                    } catch (SQLException e) {
                        e.printStackTrace();
                    }
                }

                if (!didInsert) {
                    logAction(guid, "update wallet failed to save payload", req.getRemoteAddr(), req.getHeader("User-Agent"));

                    throw new Exception(strings.getWallet_app().getErrors().getError_saving_wallet());
                }

                {
                    Connection conn = BitcoinDatabaseManager.conn();
                    try {
                        final WalletObject obj = WalletObject.getWallet(conn, guid);
                        if (Arrays.equals(checksum, obj.payload_checksum) && payload.equals(obj.payload)) {
                            logAction(guid, "update wallet", req.getRemoteAddr(), req.getHeader("User-Agent"));

                            res.getWriter().print(strings.getWallet_app().getSuccess().getWallet_synced());

                            //Update in background
                            GlobalExecutorService.ex.execute(new Runnable() {
                                public void run() {

                                    try {
                                        //Notify the websocket server of the change
                                        WebSocketManager.sendWalletDidChangeNotifcation(obj.guid, checksumString);
                                    } catch (Throwable e) {
                                        e.printStackTrace();
                                    }

                                    try {
                                        //Save To S3
                                        S3.saveWallet(obj.guid, obj.payload, obj.payload_checksum);
                                    } catch (Throwable e) {
                                        e.printStackTrace();
                                    }

                                    try {
                                        //Backup to Dropbox, GDrive etc
                                        backupWallet(obj);
                                    } catch (Throwable e) {
                                        e.printStackTrace();
                                    }
                                }
                            });
                        } else {
                            logAction(guid, "update wallet checksum reread failed", req.getRemoteAddr(), req.getHeader("User-Agent"));

                            Format format = new Format();

                            format.setInput(strings.getWallet_app().getErrors().getChecksum_reread_failed());

                            format.setParam1(Settings.instance().getString("admin_email"));

                            throw new Exception(format.formatString());
                        }
                    } finally {
                        BitcoinDatabaseManager.close(conn);
                    }
                }

            } else if (method.equals("update-ip-lock-on")) {
                boolean isOn;
                try {
                    isOn = Boolean.valueOf(payload);
                } catch (Exception e) {
                    throw new Exception(strings.getWallet_app().getErrors().getInvalid_payload());
                }

                logAction(guid, "toggle ip lock " + isOn, req.getRemoteAddr(), req.getHeader("User-Agent"));

                Connection conn = BitcoinDatabaseManager.conn();

                PreparedStatement update_smt = null;
                try {
                    update_smt = conn.prepareStatement("update bitcoin_wallets set ip_lock_on = ? where guid = ? and shared_key = ?");

                    if (isOn)
                        update_smt.setInt(1, 1);
                    else
                        update_smt.setInt(1, 0);


                    update_smt.setString(2, guid);
                    update_smt.setString(3, sharedKey);

                    if (update_smt.executeUpdate() == 1) {
                        res.getWriter().print(strings.getWallet_app().getSuccess().getUpdated_ip_lock());
                    } else {
                        res.setStatus(500);
                        res.getWriter().print(strings.getWallet_app().getErrors().getError_updating_ip_lock());
                    }

                } finally {
                    BitcoinDatabaseManager.close(update_smt);
                    BitcoinDatabaseManager.close(conn);
                }

            } else if (method.equals("update-ip-lock")) {
                final String PATTERN = "^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
                        "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
                        "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
                        "([01]?\\d\\d?|2[0-4]\\d|25[0-5])$";

                Pattern pattern = Pattern.compile(PATTERN);

                Set<String> ipsSet = new HashSet<>();
                String[] ips = payload.split(",", Pattern.LITERAL);
                for (String input_ip : ips) {
                    String trimmed_ip = Jsoup.parse(input_ip.trim()).text();

                    if (trimmed_ip.length() == 0)
                        continue;

                    if (!pattern.matcher(trimmed_ip).matches()) {
                        throw new Exception(strings.getWallet_app().getErrors().getInvalid_ip_address());
                    }

                    ipsSet.add(trimmed_ip);
                }

                logAction(guid, "update ip lock " + ipsSet, req.getRemoteAddr(), req.getHeader("User-Agent"));

                String outputString = StringUtils.join(ipsSet, ",");

                Connection conn = BitcoinDatabaseManager.conn();
                PreparedStatement update_smt = null;
                try {
                    update_smt = conn.prepareStatement("update bitcoin_wallets set ip_lock = ? where guid = ? and shared_key = ?");

                    update_smt.setString(1, outputString);
                    update_smt.setString(2, guid);
                    update_smt.setString(3, sharedKey);

                    if (update_smt.executeUpdate() == 1) {
                        res.getWriter().print(strings.getWallet_app().getSuccess().getUpdated_ip_address());
                    } else {
                        res.setStatus(500);
                        res.getWriter().print(strings.getWallet_app().getErrors().getError_updating_ip_address());
                    }
                }  finally {
                    BitcoinDatabaseManager.close(update_smt);
                    BitcoinDatabaseManager.close(conn);
                }

            } else if (method.equals("update-notifications-type")) {

                String[] types = payload.split("\\|");

                if (types.length > 8)
                    throw new Exception(strings.getWallet_app().getErrors().getInvalid_payload());

                BitField notifications_type = new BitField();
                for (int ii = 0; ii < types.length; ++ii) {
                    try {
                        notifications_type.enable(Integer.valueOf(types[ii]));
                    } catch (Exception e) {
                        throw new ServletException(strings.getErrors().getInvalid_numerical_value());
                    }
                }

                logAction(guid, "update notifications types " + payload, req.getRemoteAddr(), req.getHeader("User-Agent"));

                Connection conn = BitcoinDatabaseManager.conn();
                PreparedStatement update_smt = null;
                try {
                    update_smt = conn.prepareStatement("update bitcoin_wallets set notifications_type = ? where guid = ? and shared_key = ? and (notifications_disabled_until is null or (notifications_disabled_until / 1000) < UNIX_TIMESTAMP())");

                    update_smt.setInt(1, notifications_type.getCurrent());
                    update_smt.setString(2, guid);
                    update_smt.setString(3, sharedKey);

                    if (update_smt.executeUpdate() == 1) {
                        res.getWriter().print(strings.getWallet_app().getSuccess().getNotification_settings_updated());
                    } else {
                        throw new Exception(strings.getWallet_app().getErrors().getError_updating_notification_settings());
                    }
                }  finally {
                    BitcoinDatabaseManager.close(update_smt);
                    BitcoinDatabaseManager.close(conn);
                }

            } else if (method.equals("update-notifications-on") || method.equals("update-notifications-confirmations")) {
                Connection conn = BitcoinDatabaseManager.conn();

                PreparedStatement update_smt = null;
                try {
                    if (method.equals("update-notifications-on"))
                        update_smt = conn.prepareStatement("update bitcoin_wallets set notifications_on = ? where guid = ? and shared_key = ?");
                    else if (method.equals("update-notifications-confirmations"))
                        update_smt = conn.prepareStatement("update bitcoin_wallets set notifications_confirmations = ? where guid = ? and shared_key = ?");

                    try {
                        update_smt.setInt(1, Integer.valueOf(payload).intValue());
                    } catch (Exception e) {
                        throw new Exception(strings.getWallet_app().getErrors().getInvalid_payload());
                    }

                    update_smt.setString(2, guid);
                    update_smt.setString(3, sharedKey);

                    if (update_smt.executeUpdate() == 1) {
                        res.getWriter().print(strings.getWallet_app().getSuccess().getNotification_settings_updated());
                    } else {
                        throw new Exception(strings.getWallet_app().getErrors().getError_updating_notification_settings());
                    }

                } finally {
                    BitcoinDatabaseManager.close(update_smt);
                    BitcoinDatabaseManager.close(conn);
                }

            } else if (method.equals("update-logging-level")) {

                int logging_level;
                try {
                    logging_level = Integer.valueOf(payload).intValue();
                } catch (Exception e) {
                    throw new Exception(strings.getWallet_app().getErrors().getInvalid_payload());
                }

                {
                    Connection conn = BitcoinDatabaseManager.conn();
                    PreparedStatement update_smt = null;
                    try {
                        update_smt = conn.prepareStatement("update bitcoin_wallets set logging_level = ? where guid = ? and shared_key = ?");
                        update_smt.setInt(1, logging_level);
                        update_smt.setString(2, guid);
                        update_smt.setString(3, sharedKey);

                        if (update_smt.executeUpdate() == 1) {
                            logAction(guid, "update logging level " + payload, req.getRemoteAddr(), req.getHeader("User-Agent"));

                            res.getWriter().print(strings.getWallet_app().getSuccess().getLogging_level_updated());
                        } else {
                            logAction(guid, "error update logging level " + payload, req.getRemoteAddr(), req.getHeader("User-Agent"));

                            throw new Exception(strings.getWallet_app().getErrors().getError_updating_logging_level_updated());
                        }
                    } finally {
                        BitcoinDatabaseManager.close(update_smt);
                        BitcoinDatabaseManager.close(conn);
                    }
                }
            } else if (method.equals("update-auth-type")) {

                int auth_type = 0;
                try {
                    auth_type = Integer.valueOf(payload).intValue();
                } catch (Exception e) {
                    throw new Exception(strings.getWallet_app().getErrors().getInvalid_payload());
                }

                {
                    Connection conn = BitcoinDatabaseManager.conn();
                    PreparedStatement update_smt = null;
                    try {
                        update_smt = conn.prepareStatement("update bitcoin_wallets set auth_type = ?, failed_logins = 0 where guid = ? and shared_key = ?");
                        update_smt.setInt(1, auth_type);
                        update_smt.setString(2, guid);
                        update_smt.setString(3, sharedKey);

                        if (update_smt.executeUpdate() == 1) {
                            logAction(guid, "update auth type " + payload, req.getRemoteAddr(), req.getHeader("User-Agent"));

                            res.getWriter().print(strings.getWallet_app().getSuccess().getTwo_factor_authentication_updated());
                        } else {
                            logAction(guid, "error update auth type " + payload, req.getRemoteAddr(), req.getHeader("User-Agent"));

                            throw new Exception(strings.getWallet_app().getErrors().getError_updating_two_factor_authentication());
                        }

                    } finally {
                        BitcoinDatabaseManager.close(update_smt);
                        BitcoinDatabaseManager.close(conn);
                    }
                }

                if (auth_type == AuthTypeGoogleAuthenticator) {
                    String new_secret = GoogleAuthenticator.generateSecret();

                    Connection conn = BitcoinDatabaseManager.conn();
                    PreparedStatement update_secret_smt = null;
                    try {
                        update_secret_smt = conn.prepareStatement("update bitcoin_wallets set google_secret = ? where guid = ? and shared_key = ?");
                        update_secret_smt.setString(1, new_secret);
                        update_secret_smt.setString(2, guid);
                        update_secret_smt.setString(3, sharedKey);

                        if (update_secret_smt.executeUpdate() == 1) {
                            logAction(guid, "update google authenticator secret", req.getRemoteAddr(), req.getHeader("User-Agent"));

                            res.getWriter().print(strings.getWallet_app().getSuccess().getGoogle_secret_generated());
                        } else {
                            logAction(guid, "error update google authenticator secret", req.getRemoteAddr(), req.getHeader("User-Agent"));

                            throw new Exception(strings.getWallet_app().getErrors().getError_generating_google_secret());
                        }

                    } finally {
                        BitcoinDatabaseManager.close(update_secret_smt);
                        BitcoinDatabaseManager.close(conn);
                    }
                }

            } else if (method.equals("update-skype")) {

                Connection conn = BitcoinDatabaseManager.conn();

                PreparedStatement update_smt = null;
                try {
                    update_smt = conn.prepareStatement("update bitcoin_wallets set skype_username = ? where guid = ? and shared_key = ?");
                    update_smt.setString(1, payload.trim());
                    update_smt.setString(2, guid);
                    update_smt.setString(3, sharedKey);

                    if (update_smt.executeUpdate() == 1) {
                        logAction(guid, "update skype", req.getRemoteAddr(), req.getHeader("User-Agent"));

                        res.getWriter().print(strings.getWallet_app().getSuccess().getSkype_updated());
                    } else {
                        logAction(guid, "error update skype", req.getRemoteAddr(), req.getHeader("User-Agent"));

                        throw new Exception(strings.getWallet_app().getErrors().getError_updating_skype());
                    }

                } finally {
                    BitcoinDatabaseManager.close(update_smt);
                    BitcoinDatabaseManager.close(conn);
                }

            } else if (method.equals("update-boxcar")) {
                Connection conn = BitcoinDatabaseManager.conn();

                String email = payload.trim();

                if (!isValidEmailAddress(email)) {
                    logAction(guid, "update invalid email", req.getRemoteAddr(), req.getHeader("User-Agent"));

                    throw new Exception(strings.getWallet_app().getErrors().getInvalid_email());
                }

                PreparedStatement update_smt = null;
                try {
                    update_smt = conn.prepareStatement("update bitcoin_wallets set boxcar_email = ? where guid = ? and shared_key = ?");
                    update_smt.setString(1, email);
                    update_smt.setString(2, guid);
                    update_smt.setString(3, sharedKey);

                    if (update_smt.executeUpdate() == 1) {
                        logAction(guid, "update email", req.getRemoteAddr(), req.getHeader("User-Agent"));

                        res.getWriter().print(strings.getWallet_app().getSuccess().getEmail_updated());
                    } else {
                        logAction(guid, "error update email", req.getRemoteAddr(), req.getHeader("User-Agent"));

                        throw new Exception(strings.getWallet_app().getErrors().getError_updating_email());
                    }

                } finally {
                    BitcoinDatabaseManager.close(update_smt);
                    BitcoinDatabaseManager.close(conn);
                }

                Boxcar.subscribe(email);

            } else if (method.equals("update-password-hint1") || method.equals("update-password-hint2")) {
                payload = Jsoup.parse(payload.trim()).text();

                Connection conn = BitcoinDatabaseManager.conn();

                PreparedStatement update_smt = null;
                try {
                    if (method.equals("update-password-hint1"))
                        update_smt = conn.prepareStatement("update bitcoin_wallets set password_hint1 = ? where guid = ? and shared_key = ?");
                    else
                        update_smt = conn.prepareStatement("update bitcoin_wallets set password_hint2 = ? where guid = ? and shared_key = ?");

                    update_smt.setString(1, payload.trim());
                    update_smt.setString(2, guid);
                    update_smt.setString(3, sharedKey);

                    if (update_smt.executeUpdate() == 1) {
                        logAction(guid, "update password hint", req.getRemoteAddr(), req.getHeader("User-Agent"));

                        res.getWriter().print(strings.getWallet_app().getSuccess().getUpdated_password_hint());
                    } else {
                        logAction(guid, "error update password hint", req.getRemoteAddr(), req.getHeader("User-Agent"));

                        throw new Exception(strings.getWallet_app().getErrors().getError_updating_password_hint());
                    }

                } finally {
                    BitcoinDatabaseManager.close(update_smt);
                    BitcoinDatabaseManager.close(conn);
                }

            } else if (method.equals("update-yubikey")) {

                String otp = payload.trim();

                if (!YubicoClient.isValidOTPFormat(otp)) {
                    logAction(guid, "update yubikey invalid otp format", req.getRemoteAddr(), req.getHeader("User-Agent"));

                    throw new Exception(strings.getWallet_app().getErrors().getInvalid_payload());
                }

                YubicoClient client = YubicoClient.getClient(4711);

                YubicoResponse response = client.verify(otp);

                if (response.getStatus() != YubicoResponseStatus.OK) {
                    logAction(guid, "update yubikey invalid code", req.getRemoteAddr(), req.getHeader("User-Agent"));

                    throw new Exception(strings.getWallet_app().getErrors().getAuthentication_code_incorrect());
                }

                Connection conn = BitcoinDatabaseManager.conn();
                PreparedStatement update_smt = null;

                try {
                    update_smt = conn.prepareStatement("update bitcoin_wallets set yubikey = ?, failed_logins = 0 where guid = ? and shared_key = ?");
                    update_smt.setString(1, YubicoClient.getPublicId(payload));
                    update_smt.setString(2, guid);
                    update_smt.setString(3, sharedKey);

                    if (update_smt.executeUpdate() == 1) {
                        logAction(guid, "update yubikey", req.getRemoteAddr(), req.getHeader("User-Agent"));

                        res.getWriter().print(strings.getWallet_app().getSuccess().getYubikey_updated());
                    } else {
                        logAction(guid, "error update yubikey", req.getRemoteAddr(), req.getHeader("User-Agent"));

                        throw new Exception(strings.getWallet_app().getErrors().getError_updating_yubikey());
                    }

                } finally {
                    BitcoinDatabaseManager.close(update_smt);
                    BitcoinDatabaseManager.close(conn);
                }

            } else if (method.equals("update-sms")) {
                Phonenumber.PhoneNumber number = PhoneNumberUtil.getInstance().parse(payload, "US");

                int country_code = number.getCountryCode();

                String formattedNumber = "+" + country_code + " " +number.getNationalNumber();

                boolean updated = false;

                {
                    Connection conn = BitcoinDatabaseManager.conn();
                    PreparedStatement update_smt = null;
                    try {
                        update_smt = conn.prepareStatement("update bitcoin_wallets set sms_number = ?, sms_verified = 0 where guid = ? and shared_key = ?");
                        update_smt.setString(1, formattedNumber);
                        update_smt.setString(2, guid);
                        update_smt.setString(3, sharedKey);

                        if (update_smt.executeUpdate() == 1) {
                            logAction(guid, "update sms " + updated, req.getRemoteAddr(), req.getHeader("User-Agent"));

                            updated = true;
                        }

                    } finally {
                        BitcoinDatabaseManager.close(update_smt);
                        BitcoinDatabaseManager.close(conn);
                    }
                }

                if (updated) {
                    String code = null;
                    {
                        Connection conn = BitcoinDatabaseManager.conn();
                        try {
                            //Generate a new email code
                            code = generateAndUpdateSMSCode(conn, guid);
                        } finally {
                            BitcoinDatabaseManager.close(conn);
                        }
                    }

                    if (code == null) {
                        throw new Exception(strings.getWallet_app().getErrors().getError_generating_auth_code());
                    }

                    Format format = new Format();

                    format.setInput(strings.getNotifications().getSms_authentication_code());
                    format.setParam1(code);

                    String message = format.formatString() + " - "+ HTTPS_ROOT + "wallet/" + guid;

                    if (SMS.sendSMS(guid, formattedNumber, message, SMS.HighPriority)) {
                        res.getWriter().print(strings.getWallet_app().getSuccess().getSms_updated());
                    }  else {
                        throw new Exception(strings.getWallet_app().getErrors().getError_sending_sms_code());
                    }
                } else {
                    throw new Exception(strings.getWallet_app().getErrors().getError_updating_sms());
                }

            } else if (method.equals("verify-email")) {
                boolean didVerify = false;

                {
                    Connection conn = BitcoinDatabaseManager.conn();
                    PreparedStatement email_confirm_stmt = null;
                    try {
                        email_confirm_stmt = conn.prepareStatement("update bitcoin_wallets set email_verified = 1, email_code = null where guid = ? and shared_key = ? and UPPER(email_code) = UPPER(?)");

                        email_confirm_stmt.setString(1, guid);
                        email_confirm_stmt.setString(2, sharedKey);
                        email_confirm_stmt.setString(3, payload.trim());

                        if (email_confirm_stmt.executeUpdate() == 1) {
                            logAction(guid, "verify email", req.getRemoteAddr(), req.getHeader("User-Agent"));

                            res.getWriter().print(strings.getWallet_app().getSuccess().getEmail_verified());

                            didVerify = true;
                        } else {
                            logAction(guid, "error verifying email", req.getRemoteAddr(), req.getHeader("User-Agent"));

                            throw new UnprintableException(strings.getWallet_app().getErrors().getEmail_code_incorrect());
                        }
                    } finally {
                        BitcoinDatabaseManager.close(email_confirm_stmt);
                        BitcoinDatabaseManager.close(conn);
                    }
                }

                if (didVerify) {
                    WalletObject obj = null;

                    Connection conn = BitcoinDatabaseManager.conn();
                    try {
                        obj = WalletObject.getWallet(conn, guid);
                    } finally {
                        BitcoinDatabaseManager.close(conn);
                    }

                    sendEmailBackup(obj);
                }

            } else if (method.equals("verify-sms")) {

                Connection conn = BitcoinDatabaseManager.conn();
                PreparedStatement email_confirm_stmt = null;
                try {
                    email_confirm_stmt = conn.prepareStatement("update bitcoin_wallets set sms_verified = 1, sms_code = null where guid = ? and shared_key = ? and sms_code = ?");

                    email_confirm_stmt.setString(1, guid);
                    email_confirm_stmt.setString(2, sharedKey);
                    email_confirm_stmt.setString(3, payload.trim());

                    if (email_confirm_stmt.executeUpdate() == 1) {
                        {
                            WalletObject obj = WalletObject.getWallet(conn, guid);

                            //Un-verify all other wallets this number is associated with
                            PreparedStatement stmt = null;
                            try {
                                stmt = conn.prepareStatement("update bitcoin_wallets set sms_verified = 0 where sms_number = ? and guid != ?");

                                stmt.setString(1, obj.getSms_number());
                                stmt.setString(2, guid);

                                stmt.executeUpdate();
                            } finally {
                                BitcoinDatabaseManager.close(stmt);
                            }
                        }

                        logAction(guid, "verifying sms", req.getRemoteAddr(), req.getHeader("User-Agent"));

                        res.getWriter().print(strings.getWallet_app().getSuccess().getSms_verified());
                    } else {
                        logAction(guid, "error verifying sms", req.getRemoteAddr(), req.getHeader("User-Agent"));

                        throw new UnprintableException(strings.getWallet_app().getErrors().getSms_code_incorrect());
                    }
                } finally {
                    BitcoinDatabaseManager.close(email_confirm_stmt);
                    BitcoinDatabaseManager.close(conn);
                }

            } else if (method.equals("update-pub-keys")) {
                //Depreciated
            } else if (method.equals("update-email")) {
                if (!isValidEmailAddress(payload.trim())) {
                    logAction(guid, "update email invalid", req.getRemoteAddr(), req.getHeader("User-Agent"));

                    throw new Exception(strings.getWallet_app().getErrors().getInvalid_email());
                }

                boolean didUpdate = false;
                {
                    Connection conn = BitcoinDatabaseManager.conn();
                    PreparedStatement update_smt = null;
                    try {
                        update_smt = conn.prepareStatement("update bitcoin_wallets set email = ?, email_verified = 0 where guid = ? and shared_key = ?");
                        update_smt.setString(1, payload.trim());
                        update_smt.setString(2, guid);
                        update_smt.setString(3, sharedKey);

                        if (update_smt.executeUpdate() == 1) {
                            didUpdate = true;

                            logAction(guid, "update email " + didUpdate, req.getRemoteAddr(), req.getHeader("User-Agent"));
                        }
                    } finally {
                        BitcoinDatabaseManager.close(update_smt);
                        BitcoinDatabaseManager.close(conn);
                    }
                }

                if (didUpdate) {
                    {
                        Connection conn = BitcoinDatabaseManager.conn();
                        try {
                            //Generate a new email code
                            generateAndUpdateEmailCode(conn, guid);
                        } finally {
                            BitcoinDatabaseManager.close(conn);
                        }
                    }

                    if (sendEmailLink(guid, false)) {
                        res.getWriter().print(strings.getWallet_app().getSuccess().getEmail_updated());
                    } else {
                        res.setStatus(500);
                        res.getWriter().print(strings.getWallet_app().getErrors().getEmail_updated_eror_sending_link());
                    }
                } else {
                    throw new Exception(strings.getWallet_app().getErrors().getError_updating_email());
                }
            } else if (method.equals("get-info")) {

                String ip = req.getRemoteAddr();

                res.setContentType("application/json");

                WalletObject obj = null;
                {
                    {
                        Connection conn = BitcoinDatabaseManager.conn();
                        try {
                            obj = WalletObject.getWallet(conn, guid);
                        } finally {
                            BitcoinDatabaseManager.close(conn);
                        }
                    }

                    if (obj == null) {
                        throw new Exception(strings.getWallet_app().getErrors().getFailed_to_get_wallet());
                    }

                    if (!obj.sharedKeyMatches(sharedKey)) {
                        logAction(guid, "get account settings invalid shared key", req.getRemoteAddr(), req.getHeader("User-Agent"));

                        throw new Exception(strings.getWallet_app().getErrors().getUnauthorized());
                    }

                    JSONObject json = new JSONObject();

                    if (obj.email != null)
                        json.put("email", obj.email);

                    if (obj.secret_phrase != null)
                        json.put("phrase", obj.secret_phrase);

                    if (obj.alias != null)
                        json.put("alias", obj.alias);

                    if (obj.http_url != null)
                        json.put("http_url", obj.http_url);

                    if (obj.skype_username != null)
                        json.put("skype_username", obj.skype_username);

                    if (obj.boxcar_email != null)
                        json.put("boxcar_email", obj.boxcar_email);

                    if (obj.sms_number != null)
                        json.put("sms_number", obj.sms_number);

                    json.put("sms_verified", obj.sms_verified);
                    json.put("auth_type", obj.auth_type);
                    json.put("email_verified", obj.email_verified);
                    json.put("notifications_type",  new JSONArray(obj.notifications_type.values()));
                    json.put("notifications_on", obj.notifications_on);
                    json.put("notifications_confirmations", obj.notifications_confirmations);
                    json.put("auto_email_backup", obj.auto_email_backup);
                    json.put("never_save_auth_type", obj.never_save_auth_type);
                    json.put("logging_level", obj.logging_level);

                    if (obj.password_hint1 != null)
                        json.put("password_hint1", obj.password_hint1);

                    if (obj.password_hint2 != null)
                        json.put("password_hint2", obj.password_hint2);

                    json.put("ip_lock_on", obj.ip_lock_on);
                    json.put("my_ip", ip);

                    if (obj.ip_lock != null) {
                        json.put("ip_lock", obj.ip_lock);
                    }

                    if (obj.auth_type == AuthTypeYubikey || obj.auth_type == AuthTypeYubikeyMtGox) {
                        json.put("yubikey", obj.yubikey);
                    }

                    String google_secret = obj.google_secret;
                    if (obj.auth_type == AuthTypeGoogleAuthenticator && google_secret != null) {
                        String google_secret_url = null;
                        if (obj.alias != null) {
                            google_secret_url = GoogleAuthenticator.getQRBarcodeURL(obj.alias, "blockchain.info", google_secret);
                        } else {
                            google_secret_url = GoogleAuthenticator.getQRBarcodeURL(guid, "blockchain.info", google_secret);
                        }

                        json.put("google_secret_url", google_secret_url);
                    }

                    {
                        JSONObject currencies = new JSONObject();

                        for (CurrencyManager.Symbol symbol : CurrencyManager.getSymbols().values())
                            currencies.put(symbol.getCode(), symbol.getName());

                        json.put("currencies", currencies);
                        json.put("currency", obj.getCurrency().getCode());
                    }

                    {
                        JSONObject languages = new JSONObject();

                        for (Language language : LanguageManager.getInstance().getLanguages())
                            languages.put(language.getCode(), language.getName());

                        json.put("languages", languages);
                        json.put("language", obj.getLanguage().getCode());
                    }

                    logAction(guid, "get account settings", req.getRemoteAddr(), req.getHeader("User-Agent"));

                    res.getWriter().print(json.toJSONString());
                }
            } else if (method.equals("update-phrase")) {

                if (!StringUtils.isAlphanumericSpace(payload)) {
                    logAction(guid, "update secret phrase invalid payload", req.getRemoteAddr(), req.getHeader("User-Agent"));

                    throw new Exception(strings.getWallet_app().getErrors().getInvalid_payload());
                }

                PreparedStatement update_smt = null;
                Connection conn = BitcoinDatabaseManager.conn();
                try {
                    update_smt = conn.prepareStatement("update bitcoin_wallets set secret_phrase = ? where guid = ? and shared_key = ?");

                    update_smt.setString(1, payload);
                    update_smt.setString(2, guid);
                    update_smt.setString(3, sharedKey);

                    if (update_smt.executeUpdate() == 1) {
                        logAction(guid, "update secret phrase", req.getRemoteAddr(), req.getHeader("User-Agent"));

                        res.getWriter().print(strings.getWallet_app().getSuccess().getSecret_phrase_updated());
                    } else {
                        logAction(guid, "error update secret phrase", req.getRemoteAddr(), req.getHeader("User-Agent"));

                        throw new Exception(strings.getWallet_app().getErrors().getError_updating_secret_phrase());
                    }

                } finally {
                    BitcoinDatabaseManager.close(update_smt);
                    BitcoinDatabaseManager.close(conn);
                }
            } else if (method.equals("update-auto-email-backup")) {
                logAction(guid, "update auto email backups", req.getRemoteAddr(), req.getHeader("User-Agent"));

                PreparedStatement update_smt = null;
                Connection conn = BitcoinDatabaseManager.conn();
                try {
                    update_smt = conn.prepareStatement("update bitcoin_wallets set auto_email_backup = ? where guid = ? and shared_key = ?");

                    if (payload.equals("true"))
                        update_smt.setInt(1, 1);
                    else
                        update_smt.setInt(1, 0);

                    update_smt.setString(2, guid);
                    update_smt.setString(3, sharedKey);

                    if (update_smt.executeUpdate() == 1) {
                        if (payload.equals("true"))
                            res.getWriter().print(strings.getWallet_app().getSuccess().getAuto_backup_enabled());
                        else
                            res.getWriter().print(strings.getWallet_app().getSuccess().getAuto_backup_disabled());

                    } else {
                        throw new Exception(strings.getWallet_app().getErrors().getError_updating_auto_backup());
                    }

                } finally {
                    BitcoinDatabaseManager.close(update_smt);
                    BitcoinDatabaseManager.close(conn);
                }

            } else if (method.equals("update-never-save-auth-type")) {
                logAction(guid, "update never save auth type", req.getRemoteAddr(), req.getHeader("User-Agent"));

                PreparedStatement update_smt = null;
                Connection conn = BitcoinDatabaseManager.conn();
                try {
                    update_smt = conn.prepareStatement("update bitcoin_wallets set never_save_auth_type = ? where guid = ? and shared_key = ?");

                    if (payload.equals("true"))
                        update_smt.setInt(1, 1);
                    else
                        update_smt.setInt(1, 0);

                    update_smt.setString(2, guid);
                    update_smt.setString(3, sharedKey);

                    if (update_smt.executeUpdate() == 1) {
                        if (payload.equals("true"))
                            res.getWriter().print(strings.getWallet_app().getSuccess().getSuccess());
                        else
                            res.getWriter().print(strings.getWallet_app().getSuccess().getSuccess());

                    } else {
                        throw new Exception(strings.getWallet_app().getErrors().getError_updating_auth_saving());
                    }

                } finally {
                    BitcoinDatabaseManager.close(update_smt);
                    BitcoinDatabaseManager.close(conn);
                }

            } else if (method.equals("update-alias")) {

                String alias = payload.trim();

                if (!validateAlias(alias)) {
                    logAction(guid, "update alias invalid", req.getRemoteAddr(), req.getHeader("User-Agent"));

                    throw new Exception(strings.getWallet_app().getErrors().getInvalid_alias());
                }

                if (alias.length() > 35) {
                    logAction(guid, "update alias too long", req.getRemoteAddr(), req.getHeader("User-Agent"));

                    throw new Exception(strings.getWallet_app().getErrors().getAlias_too_long());
                }

                Connection conn = BitcoinDatabaseManager.conn();

                PreparedStatement update_smt = null;

                try {
                    if (aliasIsInUse(conn, alias)) {
                        logAction(guid, "update alias already in use", req.getRemoteAddr(), req.getHeader("User-Agent"));

                        throw new UnprintableException(strings.getWallet_app().getErrors().getError_alias_taken());
                    }

                    update_smt = conn.prepareStatement("update bitcoin_wallets set alias = ? where guid = ? and shared_key = ?");

                    update_smt.setString(1, alias);
                    update_smt.setString(2, guid);
                    update_smt.setString(3, sharedKey);

                    if (update_smt.executeUpdate() == 1) {
                        logAction(guid, "update alias", req.getRemoteAddr(), req.getHeader("User-Agent"));

                        res.getWriter().print(strings.getWallet_app().getSuccess().getAlias_updated());
                    } else {
                        logAction(guid, "error update alias", req.getRemoteAddr(), req.getHeader("User-Agent"));

                        throw new Exception(strings.getWallet_app().getErrors().getError_updating_alias());
                    }

                } finally {
                    BitcoinDatabaseManager.close(update_smt);
                    BitcoinDatabaseManager.close(conn);
                }
            } else if (method.equals("update-language")) {

                String code = payload.trim().toLowerCase();

                if (code.length() <= 1 || code.length() > 5) {
                    throw new Exception(strings.getWallet_app().getErrors().getInvalid_payload());
                }

                Language language = LanguageManager.getInstance().getLanguage(code);
                if (language == null) {
                    throw new Exception(strings.getWallet_app().getErrors().getUnknown_language_code());
                }

                putCookie(req, res, "clang", code);

                Connection conn = BitcoinDatabaseManager.conn();
                PreparedStatement update_smt = null;

                try {
                    update_smt = conn.prepareStatement("update bitcoin_wallets set language = ? where guid = ? and shared_key = ?");

                    update_smt.setString(1, code);
                    update_smt.setString(2, guid);
                    update_smt.setString(3, sharedKey);

                    if (update_smt.executeUpdate() == 1) {
                        logAction(guid, "update language", req.getRemoteAddr(), req.getHeader("User-Agent"));

                        res.getWriter().print(strings.getWallet_app().getSuccess().getLanguage_updated());
                    } else {
                        logAction(guid, "error update language", req.getRemoteAddr(), req.getHeader("User-Agent"));

                        throw new Exception(strings.getWallet_app().getErrors().getError_updating_language());
                    }
                } finally {
                    BitcoinDatabaseManager.close(update_smt);
                    BitcoinDatabaseManager.close(conn);
                }
            } else if (method.equals("update-country")) {

                String code = payload.trim().toUpperCase();

                if (code.length() <= 1 || code.length() >= 4) {
                    throw new Exception(strings.getWallet_app().getErrors().getInvalid_payload());
                }

                CurrencyManager.Symbol symbol = CurrencyManager.getSymbol(code);
                if (symbol == null) {
                    throw new Exception(strings.getWallet_app().getErrors().getUnknown_currency_code());
                }

                putCookie(req, res, "local", "true");
                putCookie(req, res, "currency", code);

                Connection conn = BitcoinDatabaseManager.conn();
                PreparedStatement update_smt = null;

                try {
                    update_smt = conn.prepareStatement("update bitcoin_wallets set country = ? where guid = ? and shared_key = ?");

                    update_smt.setString(1, code);
                    update_smt.setString(2, guid);
                    update_smt.setString(3, sharedKey);

                    if (update_smt.executeUpdate() == 1) {
                        logAction(guid, "update local currency", req.getRemoteAddr(), req.getHeader("User-Agent"));

                        res.getWriter().print(strings.getWallet_app().getSuccess().getLocal_currency_updated());
                    } else {
                        throw new Exception(strings.getWallet_app().getErrors().getError_updating_local_currency());
                    }
                } finally {
                    BitcoinDatabaseManager.close(update_smt);
                    BitcoinDatabaseManager.close(conn);
                }
            } else if (method.equals("email-backup")) {
                Connection conn = BitcoinDatabaseManager.conn();
                try {

                    WalletObject obj = WalletObject.getWallet(conn, guid);

                    if (!obj.sharedKeyMatches(sharedKey)) {
                        throw new Exception(strings.getWallet_app().getErrors().getUnauthorized());
                    }

                    if (obj.email == null || obj.email_verified != 1) {
                        throw new Exception(strings.getWallet_app().getErrors().getInvalid_email());
                    }

                    if (obj.emails_today >= MaxEmailsInOneDay) {
                        throw new Exception(strings.getWallet_app().getErrors().getReached_email_limit());
                    }

                    if (sendEmailBackup(obj)) {
                        logAction(guid, "send email backup", req.getRemoteAddr(), req.getHeader("User-Agent"));

                        res.getWriter().print(strings.getWallet_app().getSuccess().getWallet_backup_sent());
                    } else {
                        logAction(guid, "error sending email backup", req.getRemoteAddr(), req.getHeader("User-Agent"));

                        res.setStatus(500);
                        res.getWriter().print(strings.getWallet_app().getErrors().getError_sending_wallet_backup());
                    }

                } finally {
                    BitcoinDatabaseManager.close(conn);
                }

            } else if (method.equals("reset-two-factor")) {
                logAction(guid, "create two factor reset request", req.getRemoteAddr(), req.getHeader("User-Agent"));

                String alias = req.getParameter("alias");

                if (alias != null)
                    alias = Jsoup.parse(alias).text();

                String email = req.getParameter("email");

                if (email != null)
                    email = Jsoup.parse(email).text();

                String secret_phrase = req.getParameter("secret_phrase");

                if (secret_phrase != null)
                    secret_phrase = Jsoup.parse(secret_phrase).text();

                String skype_username = req.getParameter("skype_username");

                if (skype_username != null)
                    skype_username = Jsoup.parse(skype_username).text();

                String contact_email = req.getParameter("contact_email");

                if (contact_email != null)
                    contact_email = Jsoup.parse(contact_email).text();

                String message = req.getParameter("message");

                if (message != null)
                    message = Jsoup.parse(message).text();

                long created_time = System.currentTimeMillis();
                String hashed_ip = Util.SHA256Hex(req.getRemoteAddr());
                String email_code = UUID.randomUUID().toString();

                WalletObject obj = null;

                {
                    Connection conn = BitcoinDatabaseManager.conn();

                    try {
                        obj = WalletObject.getWallet(conn, guid);

                        if (obj == null) {
                            res.setStatus(500);
                            res.getWriter().print(strings.getWallet_app().getErrors().getWallet_identifier_not_found());
                            return;
                        }

                        if (obj.auth_type == 0 && obj.ip_lock_on == 0) {
                            res.setStatus(500);
                            res.getWriter().print(strings.getWallet_app().getErrors().getTwo_factor_authentication_not_enabled());
                            return;
                        }

                        PreparedStatement select_smt = null;

                        try {
                            select_smt = conn.prepareStatement("select count(*) from reset_two_factor_requests where guid = ?");

                            select_smt.setString(1, guid);

                            ResultSet results = select_smt.executeQuery();
                            if (results.next()) {
                                if (results.getInt(1) > 0) {
                                    res.setStatus(500);
                                    res.getWriter().print(strings.getWallet_app().getSuccess().getTwo_factor_reset_request_submitted());
                                    return;
                                }
                            }
                        } finally {
                            BitcoinDatabaseManager.close(select_smt);
                        }

                    } finally {
                        BitcoinDatabaseManager.close(conn);
                    }
                }

                boolean submitted = false;

                {
                    Connection conn = BitcoinDatabaseManager.conn();
                    PreparedStatement update_smt = null;

                    try {
                        update_smt = conn.prepareStatement("insert into reset_two_factor_requests (guid, email, alias, skype_username, secret_phrase, created, created_ip, email_code, contact_email, message) values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

                        update_smt.setString(1, guid);
                        update_smt.setString(2, email);
                        update_smt.setString(3, alias);
                        update_smt.setString(4, skype_username);
                        update_smt.setString(5, secret_phrase);
                        update_smt.setLong(6, created_time);
                        update_smt.setString(7, hashed_ip);
                        update_smt.setString(8, email_code);
                        update_smt.setString(9, contact_email);
                        update_smt.setString(10, message);

                        if (update_smt.executeUpdate() == 1) {
                            submitted = true;
                        }

                    } finally {
                        BitcoinDatabaseManager.close(update_smt);
                        BitcoinDatabaseManager.close(conn);
                    }
                }

                if (submitted) {
                    res.getWriter().print("Two factor Authentication Request Submitted");

                    NotificationsManager.sendMail(Settings.instance().getString("admin_email"), "Two Factor Authentication Reset Request", "A new Two-Factor Authentication Reset Request Has Been submitted for guid: " + guid +" date: " + new Date() + ". <a href=\""+HTTPS_ROOT+"two-factor-reset-requests\">View</a>");

                    {
                        if (obj.email != null && email != null && obj.email.equals(email) && obj.emails_today < MaxEmailsInOneDay) {

                            Map<String, String> params = new HashMap<>();

                            params.put("code", email_code);

                            String template = EmailTemplate.getTemplate(obj.guid, "new-two-factor-reset-request", obj.language, params);

                            NotificationsManager.sendMail(obj.email, strings.getNotifications().getTwo_factor_reset_title(), template);

                            Connection conn = BitcoinDatabaseManager.conn();
                            try {
                                incrementEmailCount(conn, guid);
                            } finally {
                                BitcoinDatabaseManager.close(conn);
                            }
                        }
                    }

                } else {
                    res.setStatus(500);
                    res.getWriter().print(strings.getWallet_app().getErrors().getError_creating_two_factor_reset_request());
                }

                return;
            } else if (method.equals("get-wallet")) {
                logAction(guid, "called two factor auth", req.getRemoteAddr(), req.getHeader("User-Agent"));

                //Get Wallet is called by the javascript client when two-factor authentication is enabled

                boolean login_did_fail = false;

                WalletObject obj = null;

                {
                    Connection conn = BitcoinDatabaseManager.conn();
                    try {
                        obj = WalletObject.getWallet(conn, guid);
                    } finally {
                        BitcoinDatabaseManager.close(conn);
                    }
                }

                try {
                    if (obj == null) {
                        throw new Exception(strings.getWallet_app().getErrors().getUnknown_identifier());
                    }

                    if (obj.account_locked_time > now) {
                        logAction(guid, "get wallet called with account locked", req.getRemoteAddr(), req.getHeader("User-Agent"));

                        throw new Exception(strings.getWallet_app().getErrors().getAccount_locked());
                    }

                    if (obj.ip_lock_on == 1 && obj.ip_lock != null && !obj.ip_lock.contains(req.getRemoteAddr())) {
                        logAction(guid, "get wallet called from incorrect ip", req.getRemoteAddr(), req.getHeader("User-Agent"));

                        throw new Exception(strings.getWallet_app().getErrors().getAccount_locked_to_another_ip());
                    }

                    //Not Two factor authenitcation just print the wallet data
                    if (obj.auth_type == AuthTypeYubikey && obj.yubikey != null) {
                        String otp = payload;

                        if (otp == null || otp.length() == 0 || otp.length() > 255) {
                            logAction(guid, "yubikey OTP invalid", req.getRemoteAddr(), req.getHeader("User-Agent"));

                            throw new Exception(strings.getWallet_app().getErrors().getAuthentication_code_invalid());
                        }

                        if (otp != null) {
                            YubicoClient client = YubicoClient.getClient(4711);

                            if (client == null)
                                throw new Exception(strings.getWallet_app().getErrors().getError_validating_yubikey());


                            if (!YubicoClient.isValidOTPFormat(otp)) {
                                logAction(guid, "yubikey OTP invalid", req.getRemoteAddr(), req.getHeader("User-Agent"));

                                login_did_fail = true;
                                throw new Exception(strings.getWallet_app().getErrors().getAuthentication_code_invalid());
                            }

                            String otpYubikey = YubicoClient.getPublicId(otp);

                            if (!otpYubikey.equals(obj.yubikey)) {
                                logAction(guid, "yubikey OTP incorrect", req.getRemoteAddr(), req.getHeader("User-Agent"));

                                login_did_fail = true;
                                throw new Exception(strings.getWallet_app().getErrors().getAuthentication_code_incorrect());
                            }

                            YubicoResponse response = client.verify(otp);

                            if (response.getStatus() == YubicoResponseStatus.OK) {

                                if (obj.never_save_auth_type == 0)
                                    setSessionValue(req, res, SAVED_AUTH_TYPE_KEY, obj.auth_type, 1440);

                                logAction(guid, "yubikey auth success", req.getRemoteAddr(), req.getHeader("User-Agent"));

                                //Everything ok, output the encrypted payload
                                res.getWriter().print(obj.payload);
                            } else {
                                logAction(guid, "yubikey OTP verification failed", req.getRemoteAddr(), req.getHeader("User-Agent"));

                                login_did_fail = true;
                                throw new Exception(strings.getWallet_app().getErrors().getAuthentication_code_incorrect());
                            }
                        }
                    } else if (obj.auth_type == AuthTypeYubikeyMtGox && obj.yubikey != null) {

                        //For mount gox keys we only check the key identity and don't validate it with the OTP server
                        String otp = payload;

                        if (otp == null || otp.length() == 0 || otp.length() > 255)
                            throw new Exception(strings.getWallet_app().getErrors().getAuthentication_code_invalid());

                        if (!YubicoClient.isValidOTPFormat(otp)) {
                            logAction(guid, "yubikey OTP incorrect", req.getRemoteAddr(), req.getHeader("User-Agent"));

                            login_did_fail = true;
                            throw new Exception(strings.getWallet_app().getErrors().getAuthentication_code_invalid());
                        }

                        String otpYubikey = YubicoClient.getPublicId(otp);

                        if (!otpYubikey.equals(obj.yubikey)) {
                            logAction(guid, "yubikey OTP verification failed", req.getRemoteAddr(), req.getHeader("User-Agent"));

                            login_did_fail = true;
                            throw new Exception(strings.getWallet_app().getErrors().getAuthentication_code_incorrect());
                        } else {

                            if (obj.never_save_auth_type == 0)
                                setSessionValue(req, res, SAVED_AUTH_TYPE_KEY, obj.auth_type, 1440);

                            logAction(guid, "yubikey auth success", req.getRemoteAddr(), req.getHeader("User-Agent"));

                            res.getWriter().print(obj.payload);
                        }

                    } else if (obj.auth_type == AuthTypeEmail && obj.email_code != null) {
                        //Check email code

                        String code = payload;

                        if (code == null || code.length() != EmailCodeLength)
                            throw new Exception(strings.getWallet_app().getErrors().getAuthentication_code_invalid());

                        if (code.equals(obj.email_code)) {

                            if (obj.never_save_auth_type == 0)
                                setSessionValue(req, res, SAVED_AUTH_TYPE_KEY, obj.auth_type, 43200);

                            logAction(guid, "email auth success", req.getRemoteAddr(), req.getHeader("User-Agent"));

                            //Login successful
                            res.getWriter().print(obj.payload);
                        } else {
                            logAction(guid, "email auth token incorrect", req.getRemoteAddr(), req.getHeader("User-Agent"));

                            login_did_fail = true;
                            throw new Exception(strings.getWallet_app().getErrors().getAuthentication_code_incorrect());
                        }

                    } else if (obj.auth_type == AuthTypeSMS && obj.sms_code != null) {
                        //Check SMS code

                        String code = payload;

                        if (code == null || code.length() != SMSCodeLength) {
                            throw new Exception(strings.getWallet_app().getErrors().getAuthentication_code_invalid());
                        }

                        if (code.equals(obj.sms_code)) {

                            if (obj.never_save_auth_type == 0)
                                setSessionValue(req, res, SAVED_AUTH_TYPE_KEY, obj.auth_type, 86400);

                            logAction(guid, "sms auth success", req.getRemoteAddr(), req.getHeader("User-Agent"));

                            //Login successful
                            res.getWriter().print(obj.payload);
                        } else {
                            logAction(guid, "sms auth token incorrect", req.getRemoteAddr(), req.getHeader("User-Agent"));

                            login_did_fail = true;
                            throw new Exception(strings.getWallet_app().getErrors().getAuthentication_code_incorrect());
                        }

                    } else if (obj.auth_type == AuthTypeGoogleAuthenticator && obj.google_secret != null) {
                        Long code = null;
                        try {
                            code = Long.valueOf(payload);
                        } catch (Exception e) {
                            logAction(guid, "google auth token invalid", req.getRemoteAddr(), req.getHeader("User-Agent"));

                            throw new Exception(strings.getWallet_app().getErrors().getAuthentication_code_invalid());
                        }

                        //We blacklist the last google authenticator code
                        //Stop a keylogger grabbing the code and loggin in again within the 30 seconds window
                        Boolean exists = (Boolean) Cache.get(guid+"-gauth-"+code);

                        if (exists != null && exists == true) {
                            logAction(guid, "google auth token reused", req.getRemoteAddr(), req.getHeader("User-Agent"));

                            throw new Exception(strings.getWallet_app().getErrors().getAuthentication_code_used_already());
                        }

                        //time window of 30 seconds (30,000 milliseconds)
                        if (GoogleAuthenticator.check_code(obj.google_secret, code, 3)) {
                            Cache.put(guid+"-gauth-"+code, true, 1800);

                            if (obj.never_save_auth_type == 0)
                                setSessionValue(req, res, SAVED_AUTH_TYPE_KEY, obj.auth_type, 1440);

                            logAction(guid, "google auth success", req.getRemoteAddr(), req.getHeader("User-Agent"));

                            //Everything ok, output the encrypted payload
                            res.getWriter().print(obj.payload);
                        } else {
                            logAction(guid, "google auth token incorrect", req.getRemoteAddr(), req.getHeader("User-Agent"));

                            login_did_fail = true;

                            throw new Exception(strings.getWallet_app().getErrors().getAuthentication_code_incorrect());
                        }
                    } else {
                        res.getWriter().print(obj.payload);
                    }
                } catch (Exception e) {
                    if (BaseServlet.log) e.printStackTrace();

                    res.setStatus(500);

                    if (login_did_fail) {
                        logAction(guid, "failed two factor login", req.getRemoteAddr(), req.getHeader("User-Agent"));

                        RequestLimiter.exceptionPenalty(req.getRemoteAddr());

                        if (obj.failed_logins >= MaxFailedLogins) {
                            if (lockAccount(obj, 240))
                                res.getWriter().print(StringEscapeUtils.escapeHtml(e.getLocalizedMessage()) + " - " + strings.getWallet_app().getErrors().getAccount_locked());

                        } else {
                            Format format = new Format();

                            format.setInput(strings.getWallet_app().getErrors().getLogin_attempts_left());

                            format.setParam1(""+(MaxFailedLogins - obj.failed_logins));

                            res.getWriter().print(StringEscapeUtils.escapeHtml(e.getLocalizedMessage()) + " - " + format.formatString());

                            Connection conn = BitcoinDatabaseManager.conn();
                            try {
                                incrementFailedLogins(conn, guid);
                            } finally {
                                BitcoinDatabaseManager.close(conn);
                            }
                        }
                    } else {
                        res.getWriter().print(StringEscapeUtils.escapeHtml(e.getLocalizedMessage()));
                    }

                } finally {
                    if (!login_did_fail) {
                        clearAuthCodes(guid);
                    }
                }
            }

        } catch (Exception e) {
            e.printStackTrace();

            AdminServlet.notifyException("Wallet Servlet Exception", e);

            RequestLimiter.didRequest(req.getRemoteAddr(), 25); //Limited to approx 6 failed tries every 4 hours (Global over whole site)

            printHTTP(req);

            res.setStatus(500);

            if (e.getLocalizedMessage() != null)
                res.getWriter().print(StringEscapeUtils.escapeHtml(e.getLocalizedMessage()));
            else
                res.getWriter().print(strings.getMisc().getUnknown_exception());

            e.printStackTrace();
        }
    }
}
