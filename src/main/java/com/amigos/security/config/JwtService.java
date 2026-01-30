package com.amigos.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

// this class is reponsible for extracting username from jwt token
// also extracting all fields(known as claims in jwt term)

@Service
public class JwtService {
    ///  key can be generated online for demo purpose and secret key is for header part of jwt
    // https://generate-random.org/encryption-keys
    private static final String SECRET_KEY = "85ab216953efd23ade00952d5605c1e76ec8100c4a797302502904b05ed731ad";

    // this method will extract email from jwt token
    public String extractUsername(String token) { // this method will return email as username from jwt token
        return extractClaim(token, Claims::getSubject); // here subject should be as per project need. we have email as our subject
    }

    // this method will extract single claim(key:value) from jwt as per our input
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);  // get all the claims from jwt token
        return claimsResolver.apply(claims);    // by this we will be able to extract single claim from token
    }


    // this overloaded method will generate jwt token by taking only userdetails as input
    // create token by taking claims as empty hashmap and userdetails
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    // this method will generate jwt token by taking claims and userdetails as input
    // Map<String, Object> are the claims
    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())  // email is set as subject in claims in jwt
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();  // compact() will finally bundle and return the jwt token


    }

    // validate a token
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    // check whether a token is expired or not
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());

    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // extract all claim/data(key:values) from jwt token
    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())  // a secret key to verify identity of sender and also the jwt is not broken in middle along the way
                .build()
                .parseClaimsJws(token)
                .getBody();      // get all the claims in the jwt token
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);   // decode the encrypted key
        return Keys.hmacShaKeyFor(keyBytes);    // hmacShaKeyFor() is the algo for decoding secret keys
    }
}
