# Intrusion Detection System (IDS) - Minimal Setup

This is an old-style minimal structure:

- One backend file: `src/main/java/com/ids/Main.java`
- One frontend file: `frontend/index.html`
- One environment file: `.env`

## Prerequisites (Windows)

1. Java 17+
2. Maven 3.9+
3. [Npcap](https://npcap.com/) with WinPcap compatibility mode
4. Run terminal as Administrator for live packet capture

## Project Tree

```text
Intrusion-detection-system/
	.env
	pom.xml
	README.md
	frontend/
		index.html
	src/
		main/
			java/com/ids/
				Main.java
```

## Run Backend

```bash
mvn clean compile
mvn exec:java
```

Optional args:

```bash
mvn exec:java -Dexec.args="--iface Ethernet --window 10 --syn-threshold 15 --icmp-threshold 50 --log-file alerts.log"
```

## Run Frontend

Open `frontend/index.html` directly in browser.

The frontend is a single-file React demo (CDN + Babel) with mock alert data.

## License

This project is licensed under the Apache License 2.0. See LICENSE and NOTICE.
