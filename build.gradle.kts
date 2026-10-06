plugins { kotlin("jvm") version "2.2.20"; `maven-publish` }
group = "com.anyoauth"
version = "0.1.0"
repositories { mavenCentral() }
kotlin { jvmToolchain(17); compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_1_8) } }
java { withSourcesJar(); withJavadocJar() }
dependencies { testImplementation("com.google.code.gson:gson:2.13.2") }
tasks.register<JavaExec>("runConformance") { dependsOn("testClasses"); classpath = sourceSets["test"].runtimeClasspath; mainClass.set("com.anyoauth.conformance.MainKt"); standardInput = System.`in` }
publishing { publications { create<MavenPublication>("maven") { from(components["java"]); artifactId = "anyoauth-client"; pom { name.set("AnyOAuth Client"); description.set("Secret-free local login helpers"); url.set("https://github.com/AnyOAuth/anyoauth-kotlin"); licenses { license { name.set("MIT"); url.set("https://opensource.org/license/mit") } } } } } }
