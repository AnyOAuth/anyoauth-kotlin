package com.anyoauth.modelchecks
import com.anyoauth.*

fun main() {
    fun rejects(block: () -> Unit) { try { block() } catch (_: SDKError) { return }; error("Expected schema rejection") }
    val value = mutableMapOf<String, Any?>("subject" to "google:123", "provider" to "google", "providerSubject" to "123", "name" to null, "username" to null, "email" to null, "emailVerified" to false, "avatarUrl" to null, "additive" to true)
    val profile = Profile.fromJSON(value)
    check(profile.name == null && profile.provider == Provider.GOOGLE && profile.toJSON().containsKey("name"))
    value.remove("name"); rejects { Profile.fromJSON(value) }
    value["name"] = null; value["provider"] = "other"; rejects { Profile.fromJSON(value) }
    value["provider"] = "google"; value["emailVerified"] = 1; rejects { Profile.fromJSON(value) }
    check(!ApiError.fromJSON(mapOf("error" to "denied")).toJSON().containsKey("message"))
    rejects { ApiError.fromJSON(mapOf("error" to "denied", "message" to null)) }
    rejects { validateSchema("TokenResponse", mapOf("access_token" to "invalid", "token_type" to "Bearer", "expires_in" to 900, "scope" to "profile")) }
    println("Passed model decoding checks")
}
