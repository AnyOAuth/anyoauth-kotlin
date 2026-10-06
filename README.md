# com.anyoauth:anyoauth-client

Generated local-only AnyOAuth kotlin client, version 0.1.0. MIT licensed.
Schema SHA-256: 1b99cb23da24b2aa0af33d45aadf907de460185671bc29fa61402450e390d6a2; generator version: 1.
Package coordinates are not a claim of registry publication.

## Backend-mediated sign-in

The current API requires confidential backend redemption. Keep credentials on your backend.
This package has no HTTP operations. It exposes only createTransaction, pkceChallenge,
authorizationUrl and validateCallback, plus schema-derived public models and validateSchema.
Server request models are excluded from generation.

1. Register an exact HTTPS callback owned by your backend (HTTP loopback for development).
2. Create a transaction and securely bind state/verifier/expiry to the initiating app session.
   Transfer the verifier to your backend using your authenticated secure application protocol,
   never a URL. Native storage must use OS-protected storage. Timestamps are Unix seconds.
3. Open the authorization URL in an OS browser authentication session.
4. The backend validates the saved redirect, state and expiry, atomically consumes the
   transaction even on denial, redeems the code once, and issues your own application session.
5. Return control through an application-controlled mechanism. Authenticate that return;
   custom-scheme URLs are not supported as AnyOAuth registered callbacks. The native helper
   can validate an HTTPS callback forwarded by your backend, but cannot replace backend validation.

Never store verifier/tokens in URLs. Helpers do not provide persistence, browser binding,
or atomic consumption. Repeated validation alone does not prevent replay.
Only Google/GitHub and S256 are supported. Origins reject credentials, path, query and fragment;
callbacks reject credentials/query/fragment at registration and match the saved URL exactly.
Duplicate query parameters (including percent-encoded aliases) are rejected on callback.

## Usage

```kotlin
val client = AnyOAuth("your-public-client-id")
val transaction = client.createTransaction()
val url = client.authorizationUrl("google", "https://your-backend.example/auth/callback", transaction.state, transaction.codeChallenge)
```

Decode models through fromJSON to validate required fields, types,
nullability, enum/constant values and schema constraints. Optional response additions are accepted.
Use validateSchema for array/string aliases. Model constructors are value containers;
decoders perform validation. No response model triggers network access.

## Build and conformance (from this package directory)

```sh
gradle build runConformance < input.json
# Direct compiler alternative (Gson is runner-only):
mkdir -p build
curl -fL https://repo.maven.apache.org/maven2/com/google/code/gson/gson/2.13.2/gson-2.13.2.jar -o build/gson-2.13.2.jar
kotlinc src/main/kotlin/com/anyoauth/AnyOAuth.kt -jvm-target 1.8 -d build/anyoauth-client.jar
kotlinc src/test/kotlin/com/anyoauth/conformance/Main.kt src/test/kotlin/com/anyoauth/modelchecks/Main.kt -classpath build/anyoauth-client.jar:build/gson-2.13.2.jar -include-runtime -d build/conformance.jar
java -cp build/conformance.jar:build/anyoauth-client.jar:build/gson-2.13.2.jar com.anyoauth.modelchecks.MainKt
java -cp build/conformance.jar:build/anyoauth-client.jar:build/gson-2.13.2.jar com.anyoauth.conformance.MainKt < input.json
```

Pure Kotlin/JVM library: Java 8 bytecode, JDK 17 build toolchain, Android API 26+ (java.util.Base64). No Android plugin or runtime JSON dependency. Gradle 8.14+ recommended; no wrapper binaries are shipped. Maven publication uses com.anyoauth:anyoauth-client. Gson 2.13.2 is pinned and used only by the conformance executable.

The runner reads one JSON object from stdin and writes one JSON object to stdout.
Build tools may log to stderr; run the built executable for protocol-only output.
Run the cross-language protocol suite with Node 18+: node conformance.test.mjs
followed by the runner command and its arguments (for example,
node conformance.test.mjs java -cp build/conformance.jar:build/anyoauth-client.jar:build/gson-2.13.2.jar com.anyoauth.conformance.MainKt).
Input: {action, baseUrl?, clientId?, params?}. Actions: createTransaction, pkceChallenge,
authorizationUrl, validateCallback. Confidential HTTP actions return unsupported_action.
Parameters: pkceChallenge {codeVerifier}; authorizationUrl {provider, redirectUri, state,
codeChallenge}; validateCallback {callbackUrl, redirectUri, state, expiresAt}.
Output: {ok:true,result} or {ok:false,error:{status:0,code,message}}. Error messages
do not contain raw input or credentials. The canonical RFC7636 test input is:

```json
{"action":"pkceChallenge","params":{"codeVerifier":"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}}
```

Expected result: dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk hashes to
E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM.
Regenerate from the parent repository with node sdks/generate.mjs --target=kotlin.

## Source and releases

Repository: https://github.com/AnyOAuth/anyoauth-kotlin

GitHub prerelease: https://github.com/AnyOAuth/anyoauth-kotlin/releases/tag/v0.1.0

Clone this repository, then run `node verify.mjs` with the native toolchain installed to build and execute the package's conformance suite. Source is generated in the AnyOAuth monorepo; propose changes there so every language stays aligned. GitHub hosts source archives and checksums. Package registry publication is separate.

This initial source release has full advertised-method conformance coverage. Runtime line/branch coverage for the whole language matrix remains a separate release gate; see https://anyoauth.com/docs/libraries/.
