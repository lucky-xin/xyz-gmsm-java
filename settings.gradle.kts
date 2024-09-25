import java.net.URI

pluginManagement {
    resolutionStrategy {
        eachPlugin {
            if (requested.id.id.equals("org.anarres.jarjar")) {
                useModule("com.github.shevek.jarjar:jarjar-gradle:${requested.version}")
            }
        }
    }
    repositories {
        mavenLocal()
        gradlePluginPortal()
        maven("https://maven.aliyun.com/repository/public")
        maven("https://plugins.gradle.org/m2/")
        maven("https://jitpack.io")
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_PROJECT)
    repositories {
        mavenLocal()
        maven {
            url = URI.create(System.getenv("MAVEN_PUBLIC_ENDPOINT"))
            isAllowInsecureProtocol = true
            credentials {
                username = System.getenv("MAVEN_USER")
                password = System.getenv("MAVEN_PWD")
            }
        }
        maven {
            url = URI("https://maven.aliyun.com/repository/public/")
        }
        maven {
            url = URI("https://packages.confluent.io/maven/")
        }
        maven {
            url = URI("https://jitpack.io")
        }
        google()
        mavenCentral()
    }
}

