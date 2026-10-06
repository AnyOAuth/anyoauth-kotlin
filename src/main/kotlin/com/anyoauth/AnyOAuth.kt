package com.anyoauth

import java.net.URI
import java.net.URLEncoder
import java.net.URLDecoder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

class SDKError(val code: String, override val message: String, val status: Int = 0): RuntimeException(message)
private fun fail(message: String): Nothing = throw SDKError("invalid_argument", message)
private fun safeURL(text: String, origin: Boolean = false, query: Boolean = false): URI {
    if (text.isEmpty() || text.any { it.isWhitespace() || it.code < 32 || it.code == 127 || it == '\\' }) fail("Unsafe URL")
    val u = try { URI(text) } catch (_: Exception) { fail("Invalid URL") }
    if (u.host.isNullOrEmpty() || u.rawUserInfo != null || u.rawFragment != null ||
        !(u.scheme == "https" || (u.scheme == "http" && u.host in listOf("localhost", "127.0.0.1", "[::1]", "::1"))) ||
        (u.port != -1 && u.port !in 1..65535) || (!query && u.rawQuery != null) ||
        (origin && u.rawPath !in listOf("", "/")) || u.rawAuthority.contains('%') || u.rawAuthority.contains('@')) fail("Unsafe URL")
    return u
}
fun validateSchema(name: String, value: Any?) {
    val schema = nativeSchemas[name] as? Map<*, *> ?: fail("Unknown model")
    validateValue(schema, value)
}
private fun validateValue(s: Map<*, *>, value: Any?) {
    val ref = s["\$ref"] as? String
    if (ref != null) { validateSchema(ref.substringAfterLast('/'), value); return }
    val types = (s["type"] as? List<*>) ?: listOf(s["type"])
    if (value == null) { if ("null" in types) return; fail("Unexpected null") }
    when (types.first { it != "null" }) {
        "string" -> {
            val v = value as? String ?: fail("Expected string")
            val length = v.codePointCount(0, v.length)
            if ((s["minLength"] as? Number)?.toInt()?.let { length < it } == true || (s["maxLength"] as? Number)?.toInt()?.let { length > it } == true) fail("Invalid string length")
            if ((s["pattern"] as? String)?.let { if (it.startsWith("^") && it.endsWith("$")) !Regex(it).matches(v) else !Regex(it).containsMatchIn(v) } == true) fail("Invalid string format")
            if ((s["enum"] as? List<*>)?.let { v !in it } == true) fail("Invalid enum")
            if (s.containsKey("const") && v != s["const"]) fail("Invalid constant")
            if (s["format"] == "uri") safeURL(v)
        }
        "integer" -> {
            val n = value as? Number ?: fail("Expected integer")
            val v = n.toDouble()
            if (!v.isFinite() || v % 1.0 != 0.0 || kotlin.math.abs(v) > 9007199254740991.0) fail("Expected safe integer")
            if (s.containsKey("const") && v != (s["const"] as Number).toDouble()) fail("Invalid constant")
        }
        "boolean" -> if (value !is Boolean) fail("Expected boolean")
        "array" -> { val values = value as? List<*> ?: fail("Expected array"); for (v in values) validateValue(s["items"] as Map<*, *>, v) }
        "object" -> {
            val m = value as? Map<*, *> ?: fail("Expected object")
            val props = s["properties"] as Map<*, *>
            for (key in (s["required"] as? List<*>) ?: emptyList<Any>()) if (!m.containsKey(key)) fail("Missing required field")
            if (s["additionalProperties"] == false && m.keys.any { !props.containsKey(it) }) fail("Unexpected field")
            for ((key, p) in props) if (m.containsKey(key)) validateValue(p as Map<*, *>, m[key])
        }
        else -> fail("Unsupported schema")
    }
}
class AnyOAuth(val clientId: String, baseUrl: String = "https://api.anyoauth.com") {
    val baseUrl: String
    init {
        safeURL(baseUrl, origin = true)
        validateValue((nativeSchemas["AuthorizationParameters"] as Map<*, *>)["properties"].let { it as Map<*, *> }["client_id"] as Map<*, *>, clientId)
        this.baseUrl = baseUrl.removeSuffix("/")
    }
    fun pkceChallenge(verifier: String): String {
        validateSchema("CodeVerifier", verifier)
        return base64url(MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(Charsets.US_ASCII)))
    }
    fun createTransaction(): Transaction {
        val rng = SecureRandom()
        fun random(): String = base64url(ByteArray(32).also { rng.nextBytes(it) })
        val state = random(); val verifier = random(); val now = System.currentTimeMillis() / 1000
        return Transaction.fromJSON(mapOf("state" to state, "codeVerifier" to verifier, "codeChallenge" to pkceChallenge(verifier), "createdAt" to now, "expiresAt" to now + 600))
    }
    fun authorizationUrl(provider: String, redirectUri: String, state: String, codeChallenge: String): String {
        val params = mapOf("client_id" to clientId, "provider" to provider, "redirect_uri" to redirectUri, "state" to state, "code_challenge" to codeChallenge, "code_challenge_method" to "S256", "response_type" to "code")
        validateSchema("AuthorizationParameters", params)
        val query = params.toSortedMap().entries.joinToString("&") { encode(it.key) + "=" + encode(it.value) }
        return URI.create(baseUrl + "/authorize?" + query).toASCIIString()
    }
    fun validateCallback(callbackUrl: String, redirectUri: String, state: String, expiresAt: Long): Map<String, String> {
        validateSchema("RedirectUri", redirectUri)
        val u = safeURL(callbackUrl, query = true)
        if (callbackUrl.substringBefore('?') != redirectUri) throw SDKError("invalid_callback", "Callback does not match saved redirect")
        if (expiresAt <= System.currentTimeMillis() / 1000) throw SDKError("transaction_expired", "Transaction expired")
        val params = mutableMapOf<String, String>()
        for (pair in u.rawQuery?.split('&') ?: emptyList()) {
            val parts = pair.split('=', limit = 2)
            val key = decode(parts[0]); val value = decode(parts.getOrElse(1) { "" })
            if (params.containsKey(key)) throw SDKError("invalid_callback", "Duplicate query parameter")
            params[key] = value
        }
        if (state.isEmpty() || params["state"] != state) throw SDKError("state_mismatch", "Callback state mismatch")
        if (params.containsKey("code") == params.containsKey("error") || (params["code"] ?: params["error"]).isNullOrEmpty()) throw SDKError("invalid_callback", "Expected exactly one code or error")
        params["code"]?.let { validateSchema("CallbackCode", it); return mapOf("code" to it, "state" to state) }
        return mapOf("error" to params.getValue("error"), "state" to state)
    }
    private fun base64url(bytes: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    private fun encode(text: String) = URLEncoder.encode(text, "UTF-8").replace("+", "%20").replace("%7E", "~")
    private fun decode(text: String): String = try {
        val decoded = URLDecoder.decode(text, "UTF-8")
        if (decoded.contains('\uFFFD')) throw SDKError("invalid_callback", "Invalid UTF-8 query")
        decoded
    } catch (e: SDKError) { throw e } catch (_: Exception) { throw SDKError("invalid_callback", "Invalid query encoding") }
}

private val nativeSchemas = mapOf<String, Any?>("Provider" to mapOf<String, Any?>("type" to "string", "enum" to listOf("google", "github")), "RedirectUri" to mapOf<String, Any?>("type" to "string", "format" to "uri", "maxLength" to 2048, "x-validation" to "redirect", "description" to "Exact registered HTTPS URL or HTTP loopback; no credentials, query or fragment."), "TokenResponse" to mapOf<String, Any?>("type" to "object", "required" to listOf("access_token", "token_type", "expires_in", "scope"), "properties" to mapOf<String, Any?>("access_token" to mapOf<String, Any?>("type" to "string", "pattern" to "^aop_[A-Za-z0-9_-]{43}\$"), "token_type" to mapOf<String, Any?>("type" to "string", "const" to "Bearer"), "expires_in" to mapOf<String, Any?>("type" to "integer", "const" to 900), "scope" to mapOf<String, Any?>("type" to "string", "const" to "profile"))), "Profile" to mapOf<String, Any?>("type" to "object", "required" to listOf("subject", "provider", "providerSubject", "name", "username", "email", "emailVerified", "avatarUrl"), "properties" to mapOf<String, Any?>("subject" to mapOf<String, Any?>("type" to "string"), "provider" to mapOf<String, Any?>("\$ref" to "#/components/schemas/Provider"), "providerSubject" to mapOf<String, Any?>("type" to "string"), "name" to mapOf<String, Any?>("type" to listOf("string", "null")), "username" to mapOf<String, Any?>("type" to listOf("string", "null")), "email" to mapOf<String, Any?>("type" to listOf("string", "null")), "emailVerified" to mapOf<String, Any?>("type" to "boolean"), "avatarUrl" to mapOf<String, Any?>("type" to listOf("string", "null")))), "ProviderStatus" to mapOf<String, Any?>("type" to "object", "required" to listOf("id", "configured", "enabled", "available"), "properties" to mapOf<String, Any?>("id" to mapOf<String, Any?>("\$ref" to "#/components/schemas/Provider"), "configured" to mapOf<String, Any?>("type" to "boolean"), "enabled" to mapOf<String, Any?>("type" to "boolean"), "available" to mapOf<String, Any?>("type" to "boolean"))), "ProviderStatuses" to mapOf<String, Any?>("type" to "array", "items" to mapOf<String, Any?>("\$ref" to "#/components/schemas/ProviderStatus")), "ApiError" to mapOf<String, Any?>("type" to "object", "required" to listOf("error"), "properties" to mapOf<String, Any?>("error" to mapOf<String, Any?>("type" to "string"), "message" to mapOf<String, Any?>("type" to "string"))), "Transaction" to mapOf<String, Any?>("type" to "object", "required" to listOf("state", "codeVerifier", "codeChallenge", "createdAt", "expiresAt"), "properties" to mapOf<String, Any?>("state" to mapOf<String, Any?>("type" to "string", "pattern" to "^[A-Za-z0-9_-]{43}\$"), "codeVerifier" to mapOf<String, Any?>("type" to "string", "pattern" to "^[A-Za-z0-9._~-]{43,128}\$"), "codeChallenge" to mapOf<String, Any?>("type" to "string", "pattern" to "^[A-Za-z0-9_-]{43}\$"), "createdAt" to mapOf<String, Any?>("type" to "integer"), "expiresAt" to mapOf<String, Any?>("type" to "integer"))), "AuthorizationParameters" to mapOf<String, Any?>("type" to "object", "additionalProperties" to false, "required" to listOf("client_id", "provider", "redirect_uri", "state", "code_challenge", "code_challenge_method", "response_type"), "properties" to mapOf<String, Any?>("client_id" to mapOf<String, Any?>("type" to "string", "minLength" to 1), "provider" to mapOf<String, Any?>("\$ref" to "#/components/schemas/Provider"), "redirect_uri" to mapOf<String, Any?>("\$ref" to "#/components/schemas/RedirectUri"), "state" to mapOf<String, Any?>("type" to "string", "minLength" to 16, "maxLength" to 512), "code_challenge" to mapOf<String, Any?>("type" to "string", "pattern" to "^[A-Za-z0-9_-]{43}\$"), "code_challenge_method" to mapOf<String, Any?>("type" to "string", "const" to "S256"), "response_type" to mapOf<String, Any?>("type" to "string", "const" to "code"))), "CodeVerifier" to mapOf<String, Any?>("type" to "string", "pattern" to "^[A-Za-z0-9._~-]{43,128}\$"), "CallbackCode" to mapOf<String, Any?>("type" to "string", "minLength" to 1, "maxLength" to 200))

enum class Provider(val wire: String) { GOOGLE("google"), GITHUB("github"); companion object { fun fromWire(value: String): Provider = entries.firstOrNull { it.wire == value } ?: throw SDKError("invalid_argument", "Invalid Provider") } }

typealias RedirectUri = String

data class TokenResponse(val access_token: String, val token_type: String, val expires_in: Long, val scope: String) {
    fun toJSON(): Map<String, Any?> = mapOf("access_token" to access_token, "token_type" to token_type, "expires_in" to expires_in, "scope" to scope)
    companion object { fun fromJSON(value: Any): TokenResponse {
        validateSchema("TokenResponse", value)
        val m = value as Map<*, *>
        return TokenResponse(m["access_token"] as String, m["token_type"] as String, (m["expires_in"] as Number).toLong(), m["scope"] as String)
    } }
}

data class Profile(val subject: String, val provider: Provider, val providerSubject: String, val name: String?, val username: String?, val email: String?, val emailVerified: Boolean, val avatarUrl: String?) {
    fun toJSON(): Map<String, Any?> = mapOf("subject" to subject, "provider" to provider.wire, "providerSubject" to providerSubject, "name" to name, "username" to username, "email" to email, "emailVerified" to emailVerified, "avatarUrl" to avatarUrl)
    companion object { fun fromJSON(value: Any): Profile {
        validateSchema("Profile", value)
        val m = value as Map<*, *>
        return Profile(m["subject"] as String, Provider.fromWire(m["provider"] as String), m["providerSubject"] as String, if (m["name"] == null) null else m["name"] as String, if (m["username"] == null) null else m["username"] as String, if (m["email"] == null) null else m["email"] as String, m["emailVerified"] as Boolean, if (m["avatarUrl"] == null) null else m["avatarUrl"] as String)
    } }
}

data class ProviderStatus(val id: Provider, val configured: Boolean, val enabled: Boolean, val available: Boolean) {
    fun toJSON(): Map<String, Any?> = mapOf("id" to id.wire, "configured" to configured, "enabled" to enabled, "available" to available)
    companion object { fun fromJSON(value: Any): ProviderStatus {
        validateSchema("ProviderStatus", value)
        val m = value as Map<*, *>
        return ProviderStatus(Provider.fromWire(m["id"] as String), m["configured"] as Boolean, m["enabled"] as Boolean, m["available"] as Boolean)
    } }
}

typealias ProviderStatuses = List<ProviderStatus>

data class ApiError(val error: String, val message: String?) {
    fun toJSON(): Map<String, Any?> = mapOf("error" to error, "message" to message).filter { (key, value) -> key !in listOf("message") || value != null }
    companion object { fun fromJSON(value: Any): ApiError {
        validateSchema("ApiError", value)
        val m = value as Map<*, *>
        return ApiError(m["error"] as String, if (m["message"] == null) null else m["message"] as String)
    } }
}

data class Transaction(val state: String, val codeVerifier: String, val codeChallenge: String, val createdAt: Long, val expiresAt: Long) {
    fun toJSON(): Map<String, Any?> = mapOf("state" to state, "codeVerifier" to codeVerifier, "codeChallenge" to codeChallenge, "createdAt" to createdAt, "expiresAt" to expiresAt)
    companion object { fun fromJSON(value: Any): Transaction {
        validateSchema("Transaction", value)
        val m = value as Map<*, *>
        return Transaction(m["state"] as String, m["codeVerifier"] as String, m["codeChallenge"] as String, (m["createdAt"] as Number).toLong(), (m["expiresAt"] as Number).toLong())
    } }
}
