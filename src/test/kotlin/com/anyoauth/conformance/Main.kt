package com.anyoauth.conformance
import com.anyoauth.*
import com.google.gson.Gson

fun main() {
    val gson = Gson()
    val output: Map<String, Any?> = try {
        val input = gson.fromJson(generateSequence(::readlnOrNull).joinToString("\n"), Map::class.java)
        val p = input["params"] as? Map<*, *> ?: emptyMap<Any, Any>()
        fun string(key: String) = p[key] as? String ?: throw SDKError("invalid_argument", "Missing string parameter")
        val client = AnyOAuth(input["clientId"] as? String ?: "conformance", input["baseUrl"] as? String ?: "https://api.anyoauth.com")
        val result: Any = when (input["action"]) {
            "pkceChallenge" -> client.pkceChallenge(string("codeVerifier"))
            "createTransaction" -> client.createTransaction().toJSON()
            "authorizationUrl" -> client.authorizationUrl(string("provider"), string("redirectUri"), string("state"), string("codeChallenge"))
            "validateCallback" -> {
                val expiry = p["expiresAt"] as? Number ?: throw SDKError("invalid_argument", "Expected integer expiry")
                val v = expiry.toDouble()
                if (!v.isFinite() || v % 1.0 != 0.0 || kotlin.math.abs(v) > 9007199254740991.0) throw SDKError("invalid_argument", "Expected integer expiry")
                client.validateCallback(string("callbackUrl"), string("redirectUri"), string("state"), expiry.toLong())
            }
            else -> throw SDKError("unsupported_action", "Client SDK supports local helpers only")
        }
        mapOf("ok" to true, "result" to result)
    } catch (e: SDKError) { mapOf("ok" to false, "error" to mapOf("status" to e.status, "code" to e.code, "message" to e.message)) }
    catch (_: Exception) { mapOf("ok" to false, "error" to mapOf("status" to 0, "code" to "invalid_argument", "message" to "Invalid runner input")) }
    println(gson.toJson(output))
}
