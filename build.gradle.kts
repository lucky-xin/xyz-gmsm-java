/*
 * Copyright 2008-present MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.io.ByteArrayOutputStream
import java.net.URI
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

buildscript {
    dependencies {
        classpath("com.github.gmazzo.buildconfig:plugin:4.1.2")
    }
}

plugins {
    idea
    `java-library`
    `maven-publish`
    signing
}

group = "xyz.encryption"
version = "1.0.4"
description = "GM SM2/SM3/SM4 encryption."

val projectName = "xyz-gmsm-java"

extra.apply {
    set("log4j.api.version", "2.10.0")
    set("slf4j.api.version", "2.0.5")

    // Testing dependencies
    set("junit.jupiter.version", "5.11.0")
    set("bcprov.jdk18on.version", "1.78.1")
    set("lombok.version", "1.18.34")
    set("fastjson2.version", "2.0.53")
}

dependencies {
    implementation("org.bouncycastle:bcprov-jdk18on:${project.extra["bcprov.jdk18on.version"]}")
    implementation("com.alibaba.fastjson2:fastjson2:${project.extra["fastjson2.version"]}")

    compileOnly("org.projectlombok:lombok:${project.extra["lombok.version"]}")
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
    options.release.set(17)
}

val defaultJdkVersion = 17
java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(defaultJdkVersion))
    }
}

/*
 * Generated files
 */
val gitVersion: String by lazy {
    val describeStdOut = ByteArrayOutputStream()
    exec {
        commandLine = listOf("git", "describe", "--tags", "--always", "--dirty")
        standardOutput = describeStdOut
    }
    describeStdOut.toString().substring(1).trim()
}

val gitDiffNameOnly: String by lazy {
    val describeStdOut = ByteArrayOutputStream()
    exec {
        commandLine = listOf("git", "diff", "--name-only")
        standardOutput = describeStdOut
    }
    describeStdOut.toString().replaceIndent(" - ")
}

tasks.withType<Test> {
    val addOpensText = project.property("add.opens") as String
    val addOpens = addOpensText.split(" ")
    jvmArgs(addOpens)

    tasks.getByName("check").dependsOn(this)
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }

    val javaVersion: Int = (project.findProperty("javaVersion") as String? ?: defaultJdkVersion.toString()).toInt()
    logger.info("Running tests using JDK$javaVersion")
    javaLauncher.set(javaToolchains.launcherFor {
        languageVersion.set(JavaLanguageVersion.of(javaVersion))
    })

    val jdkHome = project.findProperty("jdkHome") as String?
    jdkHome.let {
        val javaExecutablesPath = File(jdkHome, "bin/java")
        if (javaExecutablesPath.exists()) {
            executable = javaExecutablesPath.absolutePath
        }
    }

    addTestListener(object : TestListener {
        override fun beforeTest(testDescriptor: TestDescriptor?) {}
        override fun beforeSuite(suite: TestDescriptor?) {}
        override fun afterTest(testDescriptor: TestDescriptor?, result: TestResult?) {}
        override fun afterSuite(d: TestDescriptor?, r: TestResult?) {
            if (d != null && r != null && d.parent == null) {
                val resultsSummary = """Tests summary:
                    | ${r.testCount} tests,
                    | ${r.successfulTestCount} succeeded,
                    | ${r.failedTestCount} failed,
                    | ${r.skippedTestCount} skipped""".trimMargin().replace("\n", "")

                val border = "=".repeat(resultsSummary.length)
                logger.lifecycle("\n$border")
                logger.lifecycle("Test result: ${r.resultType}")
                logger.lifecycle(resultsSummary)
                logger.lifecycle("${border}\n")
            }
        }
    })

}

tasks.named("compileJava") {
}

/*
 * Publishing
 */
tasks.register<Jar>("sourcesJar") {
    description = "Create the sources jar"
    from(sourceSets.main.get().allSource)
    archiveClassifier.set("sources")

    into("META-INF/maven/$project.group/$project.name") {
        from(project.layout.projectDirectory.dir("mavenJava").file("pom-default.xml"))
        rename(".*", "pom.xml")
    }
}

tasks.register<Jar>("javadocJar") {
    description = "Create the Javadoc jar"
    from(tasks.javadoc)
    archiveClassifier.set("javadoc")
}


publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            artifactId = projectName
            groupId = project.group.toString()
            version = project.version.toString()

            from(components["java"])
            artifact(tasks["sourcesJar"])
            artifact(tasks["javadocJar"])

            pom {
                name.set(project.name)
                description.set(project.description)
                url.set("https://www.pistonint.com")
                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        id.set("chaoxin.lu")
                        organization.set("Piston")
                    }
                    developer {
                        id.set("chaoxin.lu")
                    }
                }
                scm {
                    connection.set("scm:https://github.com/lucky-xin/${projectName}.git")
                    developerConnection.set("scm:git@github.com/lucky-xin/${projectName}.git")
                    url.set("https://github.com/lucky-xin/${projectName}.git")
                }
            }
        }
    }

    repositories {
        maven {
            url = URI.create(System.getenv("MAVEN_RELEASE_ENDPOINT"))
            isAllowInsecureProtocol = true
            credentials {
                username = System.getenv("MAVEN_USER")
                password = System.getenv("MAVEN_PWD")
            }
        }
    }
}

tasks.javadoc {
    if (JavaVersion.current().isJava9Compatible) {
        (options as StandardJavadocDocletOptions).addBooleanOption("html5", true)
    }
}

tasks.register("publishSnapshots") {
    group = "publishing"
    description = "Publishes snapshots to Sonatype"
    if (version.toString().endsWith("-SNAPSHOT")) {
        dependsOn(tasks.withType<PublishToMavenRepository>())
    }
}

tasks.register("publishArchives") {
    group = "publishing"
    description = "Publishes a release and uploads to Sonatype / Maven Central"

    doFirst {
        if (gitVersion != version) {
            val cause = """
                | Version mismatch:
                | =================
                |
                | $version != $gitVersion
                |
                | Modified Files:
                |$gitDiffNameOnly
                |
                | The project version does not match the git tag.
                |""".trimMargin()
            throw GradleException(cause)
        } else {
            println("Publishing: ${project.name} : $gitVersion")
        }
    }

    if (gitVersion == version) {
        dependsOn(tasks.withType<PublishToMavenRepository>())
    }
}

