/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.keycloak.grids.services.impl;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.keycloak.grids.model.HttpResponseEnum;
import org.keycloak.grids.services.HttpSignatureService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tomitribe.auth.signatures.Algorithm;
import org.tomitribe.auth.signatures.Signature;
import org.tomitribe.auth.signatures.Signer;
import org.tomitribe.auth.signatures.Verifier;


import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author nikos
 */
public class HttpSignatureServiceImpl implements HttpSignatureService {

    private Algorithm algorithm = Algorithm.RSA_SHA256;
    private Signer signer;
    private final static Logger log = LoggerFactory.getLogger(HttpSignatureServiceImpl.class);

    public static String[] requiredHeaders = {"(request-target)", "host", "original-date", "digest", "x-request-id"};
    private static final String DATE_FORMAT = "EEE, dd MMM yyyy HH:mm:ss z";
    private static final int DATE_DIFF_ALLOWED = 5;

    private String keyId;
    private Key siginingKey;

    public HttpSignatureServiceImpl(String keyId, Key signingKey)
            throws InvalidKeySpecException, IOException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        try {
            this.keyId = keyId;
            this.siginingKey = signingKey;
            this.signer = new Signer(this.siginingKey, new Signature(this.keyId, algorithm, null, "(request-target)", "host", "original-date", "digest", "x-request-id"));
        } catch (Exception e) {
            log.error(e.getMessage());
        }
    }

    public String getX509PubKeytoRSABinaryFormat(PublicKey key) throws IOException, KeyStoreException {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    @Override
    public String generateSignature(String hostUrl, String method, String uri, Object postParams, String contentType, String requestId)
            throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, UnsupportedEncodingException, IOException {

        final Map<String, String> signatureHeaders = new HashMap<>();
        signatureHeaders.put("host", hostUrl);
        Date date = new Date();
        SimpleDateFormat formatter = new SimpleDateFormat("EEE, d MMM YYYY HH:mm:ss z", Locale.US);
        formatter.setTimeZone(TimeZone.getTimeZone("GMT"));
        String nowDate = formatter.format(date);
        signatureHeaders.put("original-date", nowDate);
        signatureHeaders.put("Content-Type", contentType);

        byte[] digest;
        if (postParams != null && contentType.contains("application/json")) {
            ObjectMapper mapper = new ObjectMapper();
            String updateString = mapper.writeValueAsString(postParams);
            digest = MessageDigest.getInstance("SHA-256").digest(updateString.getBytes(StandardCharsets.UTF_8));
        } else {
            if (postParams != null && contentType.contains("x-www-form-urlencoded") && postParams instanceof Map) {
                digest = MessageDigest.getInstance("SHA-256").digest(getParamsString((Map<String, String>) postParams).getBytes());
            } else {
                digest = MessageDigest.getInstance("SHA-256").digest("".getBytes());
            }
        }
        signatureHeaders.put("digest", "SHA-256=" + new String(org.tomitribe.auth.signatures.Base64.encodeBase64(digest)));
        signatureHeaders.put("Accept", "*/*");
        signatureHeaders.put("Content-Length", Integer.toString(digest.length));
        signatureHeaders.put("x-request-id", requestId);
        signatureHeaders.put("(request-target)", method + " " + uri);

        Algorithm algorithm = Algorithm.RSA_SHA256;
        Signer signer = new Signer(this.siginingKey, new Signature(this.keyId, algorithm, null, "(request-target)", "host", "original-date", "digest", "x-request-id"));
        Signature signed = signer.sign(method, uri, signatureHeaders); //getSigner(this.siginingKey, this.keyId).sign(method, uri, signatureHeaders);
        return signed.toString();
    }

    @Override
    public HttpResponseEnum verifySignature(HttpServletRequest httpRequest, Optional<PublicKey> publicKeyToCheckWith) {
        String authorization = httpRequest.getHeader("authorization");
        if (authorization != null) {

            Signature sigToVerify = Signature.fromString(authorization);
            log.info("HTTP Signature received: " + sigToVerify);
            boolean emptyRequiredHeader
                    = sigToVerify.getHeaders()
                            .stream()
                            .anyMatch(headerName -> {
                                return StringUtils.isEmpty(httpRequest.getHeader(headerName)) && !(headerName.equals("(request-target)"));
                            });
            /* Verify that all the required headers are signed (i.e. are part of the http signature)
                and that all the signed headers are present in the request
             */
            if (!sigToVerify.getHeaders().containsAll(Arrays.asList(requiredHeaders))
                    || emptyRequiredHeader) {

                log.error("error header is missing!!!");
                return HttpResponseEnum.HEADER_MISSING;
            }

            Map<String, String> headers = new HashMap<String, String>();
            Collections.list(httpRequest.getHeaderNames())
                    .stream().forEach(hName -> {
                        headers.put(hName.toLowerCase(), httpRequest.getHeader(hName));
                    });

            String clientTime = StringUtils.isEmpty(httpRequest.getHeader("date"))
                    ? httpRequest.getHeader("original-date") : httpRequest.getHeader("date");

            try {
                if (!hasValidRequestTime(clientTime)) {
                    return HttpResponseEnum.BAD_REQUEST;
                }
                byte[] requestBodyRaw = IOUtils.toByteArray(httpRequest.getInputStream());
                byte[] digest = MessageDigest.getInstance("SHA-256").digest(requestBodyRaw);
                String digestCalculated = new String(Base64.getEncoder().encodeToString(digest));

                if (!areDigestsEqual(httpRequest.getHeader("digest"), digestCalculated)) {
                    log.error("Digest missmatch");
                    return HttpResponseEnum.UN_AUTHORIZED;
                }

                String method = httpRequest.getMethod().toLowerCase();
                String uri = httpRequest.getRequestURI();
                if (!StringUtils.isEmpty(httpRequest.getQueryString())) {
                    uri += "?" + httpRequest.getQueryString();
                }
                log.debug("Veryfing signature for " + uri + " and verb " + method);

                if (isSignatureValid(sigToVerify, publicKeyToCheckWith, method, uri, headers)) {
                    return HttpResponseEnum.AUTHORIZED;
                } else {
                    log.error("could not verify signature!! from library method: " + method + " uri: " + uri);
                }
                return HttpResponseEnum.UN_AUTHORIZED;

            } catch (IllegalArgumentException e) {
                log.error("Wrong request ID");
                log.error(e.getMessage());
                return HttpResponseEnum.BAD_REQUEST;
            } catch (ParseException ex) {
                log.error("Error parsing date");
                log.error(ex.getMessage());
                return HttpResponseEnum.BAD_REQUEST;
            } catch (IOException ex) {
                log.error("ERROR getting request content");
                log.error(ex.getMessage());
                return HttpResponseEnum.BAD_REQUEST;
            } catch (NoSuchAlgorithmException ex) {
                log.error(ex.getMessage());
                return HttpResponseEnum.UN_AUTHORIZED;
            } catch (InvalidKeyException | InvalidKeySpecException | SignatureException ex) {
                log.error("Error verifying Signature");
                log.error(ex.getMessage());
                return HttpResponseEnum.UN_AUTHORIZED;
            }
        }
        return HttpResponseEnum.UN_AUTHORIZED;
    }

    public boolean hasValidRequestTime(String receivedTime) throws ParseException {
        SimpleDateFormat format = new SimpleDateFormat(DATE_FORMAT, Locale.US);
        format.setTimeZone(TimeZone.getTimeZone("GMT"));
        final Date timeServer = new Date();
        final Date timeClient = format.parse(receivedTime);
        long diff = Math.abs(timeClient.getTime() - timeServer.getTime());
        long diffMinutes = diff / (60 * 1000) % 60;
        return diffMinutes < DATE_DIFF_ALLOWED;
    }

    public boolean areDigestsEqual(String requestDigest, String calculatedDigest) {
        String reqDigestSha256;
        Pattern p = Pattern.compile("SHA-256=([^,$]+)");
        Matcher m = p.matcher(requestDigest);
        if (m.find()) {
            reqDigestSha256 = m.group(1);
            log.info("Extracted SHA-256 digest: " + reqDigestSha256);
        } else {
            return false;
        }
        return calculatedDigest.equals(reqDigestSha256);
    }

    public boolean isSignatureValid(Signature sigToVerify,
            Optional<PublicKey> publicKeyToCheckWith, String method, String uri, Map<String, String> headers) throws InvalidKeyException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException {
        Optional<PublicKey> pubKey = publicKeyToCheckWith;
        if (pubKey.isPresent()) {
            Verifier verifier = new Verifier(pubKey.get(), sigToVerify);
            return verifier.verify(method, uri, headers);
        } else {
            log.error("could not find sender key!");
        }
        return false;
    }

    public static String getParamsString(Map<String, String> params)
            throws UnsupportedEncodingException {
        StringBuilder result = new StringBuilder();

        for (Map.Entry<String, String> entry : params.entrySet()) {
            result.append(URLEncoder.encode(entry.getKey(), "UTF-8"));
            result.append("=");
            result.append(URLEncoder.encode(entry.getValue(), "UTF-8"));
            result.append("&");
        }
        String resultString = result.toString();
        return resultString.length() > 0
                ? resultString.substring(0, resultString.length() - 1)
                : resultString;
    }

    private Signer getSigner(Key sigingKey, String keyId) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, UnsupportedEncodingException, IOException {
        if (this.signer == null) {
            signer = new Signer(sigingKey, new Signature(keyId, algorithm, null, "(request-target)", "host", "original-date", "digest", "x-request-id"));
        }
        return signer;
    }

}
