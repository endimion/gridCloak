/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.keycloak.grids.services;

import io.jsonwebtoken.SignatureAlgorithm;

import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.spec.InvalidKeySpecException;

/**
 *
 * @author nikos
 */
public interface KeyStoreService {

    //Split this to http signature keys and jwt keys
    public Key getHttpSigningKey() throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, UnsupportedEncodingException;

    public Key getJwtSigningKey() throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, UnsupportedEncodingException;

    public Key getJWTPublicKey() throws KeyStoreException, UnsupportedEncodingException;

    public Key getHttpSigPublicKey() throws KeyStoreException, UnsupportedEncodingException;

    public SignatureAlgorithm getAlgorithm();

    public String getFingerPrintFromStringPubKey(String pubkey) throws NoSuchAlgorithmException, InvalidKeySpecException;
}
