package piuk.api;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.util.encoders.Base64;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import piuk.beans.BitcoinAddress;
import piuk.beans.BitcoinTx;
import piuk.beans.NoObfusticate;
import piuk.website.admin.Settings;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MtGoxClient {
    protected String key;
    protected String secret;

    public static class WalletBean implements NoObfusticate {
        public String code;
        public double balance;

        public String getCode() {
            return code;
        }

        public double getBalance() {
            return balance;
        }

        @Override
        public String toString() {
            return "WalletBean{" +
                    "code='" + code + '\'' +
                    ", balance=" + balance +
                    '}';
        }
    }

    public static class InfoBean {
        public String username;
        public Map<String, WalletBean> wallets = new HashMap<>();

        @Override
        public String toString() {
            return "InfoBean{" +
                    "username='" + username + '\'' +
                    ", wallets=" + wallets +
                    '}';
        }
    }

    public void getTickerData(CurrencyManager.Symbol symbol) throws Exception {

        Map<String, String> query_args = new HashMap<>();

        JSONObject result = (JSONObject) query("1/BTC" + symbol.getCode() + "/ticker", query_args, false);

        symbol.setLast_price(Double.valueOf((String) ((Map<String, Object>) result.get("last")).get("value")));
        symbol.setBuy_price(Double.valueOf((String) ((Map<String, Object>) result.get("buy")).get("value")));
        symbol.setSell_price(Double.valueOf((String) ((Map<String, Object>) result.get("sell")).get("value")));
    }

    public boolean withdraw(BitcoinAddress address, long amount) throws Exception {
        Map<String, String> query_args = new HashMap<>();

        query_args.put("address", address.toString());
        query_args.put("amount_int", Long.valueOf(amount).toString());

        JSONObject result = (JSONObject) query("1/generic/bitcoin/send_simple", query_args, true);

        return result != null;
    }

    public InfoBean getInfo() throws Exception {
        Map<String, String> query_args = new HashMap<>();

        JSONObject result = (JSONObject) query("1/generic/private/info", query_args, true);

        InfoBean bean = new InfoBean();

        bean.username = (String) result.get("Login");

        JSONObject wallets = (JSONObject) result.get("Wallets");

        for (Object key : wallets.keySet()) {
            JSONObject walletObj = (JSONObject) wallets.get(key);

            WalletBean walletBean = new WalletBean();

            walletBean.code = (String) key;

            walletBean.balance = Double.valueOf((String) ((JSONObject) walletObj.get("Balance")).get("value"));

            bean.wallets.put(walletBean.code, walletBean);
        }

        return bean;
    }

    public static class MtGoxOrder extends Order {
        public long reference;
        public double amount_currency;
        public String currency;
        public long amount_btc;
        public long time;

        @Override
        public long getReference() {
            return reference;
        }

        @Override
        public String getType() {
            return "BUY";
        }

        @Override
        public String getMethod() {
            return "MT.GOX";
        }

        @Override
        public long getTime() {
            return time;
        }

        @Override
        public long getAmountBTC() {
            return amount_btc;
        }

        @Override
        public double getAmountCurrency() {
            return amount_currency;
        }

        @Override
        public String getCurrency() {
            return currency;
        }

        @Override
        public boolean isPaid() {
            return true;
        }
    }

    public List<MtGoxOrder> getWalletHistory(CurrencyManager.Symbol symbol, long start, long end) throws Exception {

        final Pattern p = Pattern.compile("BTC bought: \\[tid:(\\d+)\\] (\\d+.*\\d*)BTC at .*");

        List<MtGoxOrder> all_orders = new ArrayList<>();

        int page = 0;
        while (true) {

            Map<String, String> query_args = new HashMap<>();

            query_args.put("currency", symbol.getCode());

            query_args.put("page", ""+page);

            JSONObject result = (JSONObject) query("1/generic/private/wallet/history", query_args, true);

            JSONArray results = (JSONArray) result.get("result");

            List<MtGoxOrder> orders = new ArrayList<>();


            for (Object _order_obj : results) {
                JSONObject order_obj = (JSONObject) _order_obj;

                MtGoxOrder order = new MtGoxOrder();

                order.currency = (String)((JSONObject)order_obj.get("Value")).get("currency");
                order.amount_currency = Double.valueOf((String)((JSONObject)order_obj.get("Value")).get("value"));
                order.time = ((Number)order_obj.get("Date")).longValue() * 1000;

                String info = ((String)order_obj.get("Info")).trim();

                info = info.replaceAll("[^\\x00-\\x7F]", "");

                Matcher m = p.matcher(info);

                if (m.matches()) {
                    String reference = m.group(1);
                    String amountBTC = m.group(2);

                    order.amount_btc = (long)(Double.valueOf(amountBTC)*BitcoinTx.COIN);
                    order.reference = Long.valueOf(reference);

                    if (order.time > start && order.time <= end)
                        orders.add(order);
                }
            }

            if (all_orders.size() > 0 && orders.size() == 0)
                break;

            all_orders.addAll(orders);

            ++page;
        }

        return all_orders;
    }

    public String createBidOrder(CurrencyManager.Symbol symbol, long tradeAmount) throws Exception {
        Map<String, String> query_args = new HashMap<>();

        query_args.put("type", "bid");

        query_args.put("amount_int", "" + tradeAmount);

        return (String) query("1/BTC" + symbol.getCode() + "/private/order/add", query_args, true);
    }

    public MtGoxClient() {
        this.key = Settings.instance().getString("mt_gox_api_key");
        this.secret = Settings.instance().getString("mt_gox_secret");
    }

    public Object query(String path, Map<String, String> args, boolean needsAuth) throws Exception {
        args.put("nonce", ""+new Date().getTime());

        int version = Integer.valueOf("" + path.charAt(0));

        // add nonce and build arg list
        args.put("nonce", String.valueOf(System.currentTimeMillis()));

        byte[] post_data = this.buildQueryString(args).getBytes("UTF-8");


        // build URL
        URL queryUrl = new URL("https://mtgox.com/api/" + path);

        // create connection
        HttpURLConnection connection = (HttpURLConnection) queryUrl.openConnection();
        connection.setDoOutput(true);
        // set signature
        connection.setRequestProperty("User-Agent", "Java Client (Blockchain.info)");
        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
        connection.setRequestProperty("Content-Length", "" + Integer.toString(post_data.length));
        connection.setRequestProperty("Accept-Charset", "UTF-8");

        if (needsAuth) {
            // args signature
            Mac mac = Mac.getInstance("HmacSHA512");
            SecretKeySpec secret_spec = new SecretKeySpec(Base64.decode(this.secret), "HmacSHA512");
            mac.init(secret_spec);
            String signature = new String(Base64.encode(mac.doFinal(post_data)), "UTF-8");

            connection.setRequestProperty("Rest-Key", this.key);
            connection.setRequestProperty("Rest-Sign", signature.replaceAll("\n", ""));
        }

        // write post
        connection.getOutputStream().write(post_data);

        connection.setConnectTimeout(25000);
        connection.setReadTimeout(25000);

        connection.setInstanceFollowRedirects(false);

        if (connection.getResponseCode() != 200) {
            if (connection.getErrorStream() == null && connection.getInputStream() != null)
                throw new Exception("Null Error - Response Code: " + connection.getResponseCode() + " " + IOUtils.toString(connection.getInputStream(), "UTF-8"));
            else if (connection.getErrorStream() == null)
                throw new Exception("Null Error Stream - Code: " + connection.getResponseCode());

            throw new Exception("Response Code: " + connection.getResponseCode() + " " + IOUtils.toString(connection.getErrorStream(), "UTF-8"));
        } else {

            JSONParser parser = new JSONParser();

            String response = IOUtils.toString(connection.getInputStream(), "UTF-8");

            if (response == null)
                throw new Exception("Null Response");

            JSONObject obj = (JSONObject) parser.parse(response);

            if (obj == null)
                throw new Exception("Error Parsing Response");

            if (version == 1) {
                if (obj.get("result") == null)
                    throw new Exception("Unknown Result Returned");

                if (!obj.get("result").equals("success"))
                    throw new Exception("Error Result Returned");

                return obj.get("return");

            } else if (version == 0) {
                if (obj.get("error") != null)
                    throw new Exception((String) obj.get("error"));

                return obj;
            } else {
                throw new Exception("Unknown Version");
            }
        }
    }

    protected String buildQueryString(Map<String, String> args) throws UnsupportedEncodingException {
        String result = new String();
        for (String hashkey : args.keySet()) {
            if (result.length() > 0) result += '&';

            result += URLEncoder.encode(hashkey, "UTF-8") + "=" + URLEncoder.encode(args.get(hashkey), "UTF-8");
        }
        return result;
    }
}

