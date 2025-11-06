package dev.railroadide.railroad.java;

import dev.railroadide.railroad.utility.JavaVersion;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.kordamp.ikonli.Ikon;
import org.kordamp.ikonli.fontawesome6.FontAwesomeBrands;

import java.nio.file.Path;
import java.util.Locale;
import java.util.Properties;

@ToString
@EqualsAndHashCode
public final class JDK {
    private final Path path;
    private final String name;
    private final JavaVersion version;
    private final Brand brand;

    public JDK(Path path, String name, JavaVersion version, Brand brand) {
        this.path = path;
        this.name = name;
        this.version = version;
        this.brand = brand;
    }

    public JDK(Path path, String name, JavaVersion version) {
        this.path = path;
        this.name = name;
        this.version = version;
        this.brand = Brand.from(this);
    }

    public Path path() {
        return path;
    }

    public String name() {
        return name;
    }

    public JavaVersion version() {
        return version;
    }

    public Brand brand() {
        return brand;
    }

    public enum Brand {
        ORACLE("oracle", "/images/Oracle-icon.svg"),
        ADOPTIUM("temurin", "/images/Adoptium-icon.svg", "adoptopenjdk", "adoptium", "eclipse"),
        AZUL("zulu", "/images/Azul-icon.svg", "azul"),
        CORRETTO("corretto", FontAwesomeBrands.AMAZON, "amazon"),
        BELL_SOFT("liberica", "/images/Liberica-icon.svg", "bellsoft"),
        GRAAL("graalvm", "/images/GraalVM-icon.svg", "graal"),
        SAP("sapmachine", "/images/SAP-icon.svg", "sap"),
        RED_HAT("redhat", FontAwesomeBrands.REDHAT, "red hat", "rhel"),
        MICROSOFT("microsoft", FontAwesomeBrands.MICROSOFT, "ms"),
        IBM("ibm", "/images/IBM-icon.svg", "semeru"),
        UNKNOWN("java", FontAwesomeBrands.JAVA);

        private final String key;
        private final String[] aliases;
        @Getter
        private Ikon icon;
        @Getter
        private String imagePath;

        Brand(String key, Ikon icon, String... aliases) {
            this.key = key;
            this.icon = icon;
            this.aliases = aliases;
        }

        Brand(String key, String imagePath, String... aliases) {
            this.key = key;
            this.imagePath = imagePath;
            this.aliases = aliases;
        }

        Brand(String key, Ikon icon) {
            this(key, icon, (String[]) null);
        }

        Brand(String key, String imagePath) {
            this(key, imagePath, (String[]) null);
        }

        public boolean isIkon() {
            return icon != null;
        }

        public boolean isImage() {
            return imagePath != null;
        }

        private static Brand from(JDK jdk) {
            String rawName = jdk.name();
            String path = jdk.path().toAbsolutePath().toString().toLowerCase(Locale.ROOT);
            String name = (rawName == null ? "" : rawName).toLowerCase(Locale.ROOT);
            for (Brand brand : values()) {
                if (brand == UNKNOWN)
                    continue;

                if (name.contains(brand.key) || path.contains(brand.key))
                    return brand;

                if (brand.aliases != null) {
                    for (String alias : brand.aliases) {
                        if (name.contains(alias) || path.contains(alias))
                            return brand;
                    }
                }
            }

            Properties props = JDKUtils.readReleaseProperties(jdk.path());
            String implVendor = props.getProperty("IMPLEMENTOR", "").toLowerCase(Locale.ROOT);
            for (Brand brand : values()) {
                if (brand == UNKNOWN)
                    continue;

                if (implVendor.contains(brand.key))
                    return brand;

                if (brand.aliases != null) {
                    for (String alias : brand.aliases) {
                        if (implVendor.contains(alias))
                            return brand;
                    }
                }
            }

            return UNKNOWN;
        }
    }
}
