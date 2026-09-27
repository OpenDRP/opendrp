import typer
import asyncio
import random
from datetime import datetime, timedelta, timezone
from sqlalchemy import select, text
from app.core.database import AsyncSessionLocal
from app.core.security import hash_password
from app.models import User, Asset, Breach, DrpPhishingDomain, SystemSettings
from app.schemas.user import AssetType
from app.schemas.asset import validate_and_normalize_asset_value

app = typer.Typer(help="OpenDRP demo data seeder")


@app.command()
def all(
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompts"),
    force: bool = typer.Option(False, "--force", "-f", help="Re-seed even if data exists (DELETE existing)"),
):
    """Run all seeders: users + assets + phishing + breaches."""
    asyncio.run(_seed_all(force=force))


async def _seed_all(force: bool):
    created_users = await _seed_users(force)
    print(f"[seed] Users: {created_users}")
    created_assets = await _seed_assets(force)
    print(f"[seed] Assets: {created_assets}")
    created_phishing = await _seed_phishing(force)
    print(f"[seed] Phishing threats: {created_phishing}")
    created_breaches = await _seed_breaches(force)
    print(f"[seed] HIBP breaches: {created_breaches}")
    settings = await _ensure_settings()
    print(f"[seed] System settings OK (id={settings.id})")
    print("\n✅ Seed complete! Default credentials:")
    print("   admin@example.com  : Password123  (role=admin)")
    print("   analyst@example.com: Password123  (role=analyst)")
    print("   viewer@example.com : Password123  (role=viewer)")


async def _seed_users(force: bool) -> int:
    users_data = [
        ("admin@example.com", "admin"),
        ("analyst@example.com", "analyst"),
        ("viewer@example.com", "viewer"),
    ]
    async with AsyncSessionLocal() as db:
        if force:
            await db.execute(text("TRUNCATE users CASCADE"))
            await db.commit()
        count = 0
        for email, role in users_data:
            exist = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
            if not exist:
                # Demo accounts keep ``must_change_password`` off on purpose. The
                # forced-rotation flag exists because a password an administrator
                # chose for somebody else is a shared secret; this is sample data
                # for a throwaway development database, and its password is in the
                # README on purpose so the demo login works as documented.
                u = User(email=email, password_hash=hash_password("Password123"), role=role, is_active=True)
                db.add(u)
                count += 1
        await db.commit()
        return count


async def _seed_assets(force: bool) -> int:
    assets: list[tuple[AssetType, str, str]] = [
        # type, value, criticality
        ("domain", "google.com", "critical"),
        ("domain", "example.com", "high"),
        ("domain", "github.com", "medium"),
        ("domain", "microsoft.com", "critical"),
        ("ip_address", "8.8.8.8", "high"),
        ("ip_address", "1.1.1.1", "medium"),
        ("email_account", "admin@example.com", "critical"),
        ("email_account", "ceo@example.com", "high"),
        ("email_account", "support@google.com", "medium"),
        ("keyword_domain", "paypal", "critical"),
        ("keyword_domain", "netflix", "high"),
        ("keyword_title", "Sign in to your account", "medium"),
        ("keyword_title", "Verify Your Identity", "high"),
        ("keyword_domain", "amazon", "critical"),
        ("domain", "appleid.apple.com", "critical"),
    ]
    async with AsyncSessionLocal() as db:
        if force:
            await db.execute(text("TRUNCATE assets CASCADE"))
            await db.commit()
        count = 0
        for at, av, crit in assets:
            normalized = validate_and_normalize_asset_value(at, av)
            exist = (
                await db.execute(
                    select(Asset).where(
                        Asset.asset_type == at,
                        Asset.normalized_value == normalized,
                    )
                )
            ).scalar_one_or_none()
            if not exist:
                a = Asset(
                    asset_type=at,
                    asset_value=normalized,
                    normalized_value=normalized,
                    criticality=crit,
                    is_active=True,
                )
                db.add(a)
                count += 1
        await db.commit()
        return count


#: Threat statuses the demo rows are spread over. A tuple at module level so the
#: test that pins the seeded shape cannot disagree with what was seeded.
PHISHING_STATUSES = ("active", "investigating", "resolved")


async def _seed_phishing(force: bool) -> int:
    sources = ["dnstwist", "shodan_ssl", "shodan_title", "shodan_favicon"]
    statuses = list(PHISHING_STATUSES)

    samples: list[tuple[str, str, str, str, str, str, str]] = []

    def randip() -> str:
        return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    for d in [
        "googlee.com",
        "goog1e.com",
        "google-login.com",
        "google-security.com",
        "goog1e-login.site",
        "google-verification.xyz",
        "g00gle.com",
        "google-verify.account-recovery.com",
    ]:
        samples.append(
            (
                d,
                "google.com",
                randip(),
                random.choice(sources),
                random.choice(statuses),
                random.choice(["80", "443", "80, 443", ""]),
                random.choice(["GoDaddy", "Namecheap", "Cloudflare Registrar", "Name.com", "Porkbun"]),
            )
        )
    for d in [
        "example-security.com",
        "examp1e.com",
        "exarnple.com",
        "exampie.com",
        "example-support.xyz",
        "example-login.xyz",
    ]:
        samples.append(
            (
                d,
                "example.com",
                randip(),
                random.choice(sources),
                random.choice(statuses),
                random.choice(["80, 443", "443"]),
                "Namecheap",
            )
        )
    for d in [
        "paypai.com",
        "paypa1.com",
        "paypal-verification.com",
        "paypal-login-secure.com",
        "paypal-update.biz",
        "paypal-confirm.net",
        "paypal.co-signin.site",
        "paypa1-support.com",
    ]:
        samples.append(
            (
                d,
                "paypal",
                randip(),
                random.choice(sources),
                random.choice(statuses),
                "80, 443",
                "Namecheap",
            )
        )
    for d in [
        "netflix-login-verification.com",
        "netf1ix.com",
        "netflix-signin-secure.xyz",
        "netflix-account.help",
    ]:
        samples.append(
            (
                d,
                "netflix",
                randip(),
                random.choice(sources),
                "active",
                "443",
                "Cloudflare Registrar",
            )
        )
    for d in [
        "amazon-verify.com",
        "amaz0n.com",
        "amazon-signin-secure.com",
        "amazon-update-order.com",
    ]:
        samples.append(
            (
                d,
                "amazon",
                randip(),
                random.choice(sources),
                "active",
                "80, 443",
                "GoDaddy",
            )
        )

    async with AsyncSessionLocal() as db:
        if force:
            await db.execute(text("TRUNCATE drp_phishing_domains CASCADE"))
            await db.commit()
        count = 0
        for dom, matched, ip, src, status, ports, reg in samples:
            exist = (
                await db.execute(
                    select(DrpPhishingDomain).where(DrpPhishingDomain.phishing_domain == dom)
                )
            ).scalar_one_or_none()
            if not exist:
                days_ago = random.randint(0, 29)
                created = datetime.now(timezone.utc) - timedelta(
                    days=days_ago, hours=random.randint(0, 23)
                )
                threat = DrpPhishingDomain(
                    phishing_domain=dom,
                    matched_asset=matched,
                    ip_address=ip,
                    web_ports=ports,
                    detection_source=src,
                    original_domain=matched if src == "dnstwist" else None,
                    whois_registrar=reg,
                    whois_abuse_email=f"abuse@{reg.lower().replace(' registrar','').replace(' ','')}.com".replace(
                        "..", "."
                    ),
                    domain_created_at=created - timedelta(days=random.randint(30, 365)),
                    status=status,
                    created_at=created,
                    updated_at=created,
                )
                db.add(threat)
                count += 1
        await db.commit()
        return count


async def _seed_breaches(force: bool) -> int:
    breach_samples = [
        (
            "2024-01-15",
            "LinkedIn Data Scraping",
            "LinkedIn",
            "linkedin.com",
            72000000,
            ["Email addresses", "Phone numbers", "Geographic locations", "Social connections"],
            "admin@example.com",
        ),
        (
            "2023-12-20",
            "23andMe Data Breach",
            "23andMe",
            "23andme.com",
            6900000,
            ["Email addresses", "DNA profile data", "Password hashes", "Names"],
            "ceo@example.com",
        ),
        (
            "2024-02-10",
            "Okta Support System Breach",
            "Okta",
            "okta.com",
            134000000,
            ["Email addresses", "Full names", "Session tokens", "MFA seeds"],
            "admin@example.com",
        ),
        (
            "2023-10-05",
            "MGM Resorts Cyberattack",
            "MGM Resorts",
            "mgmresorts.com",
            15000000,
            ["Drivers licenses", "Social Security numbers", "Credit cards", "Passport numbers"],
            "support@google.com",
        ),
        (
            "2024-03-18",
            "Reddit 2024 Credential Stuffing",
            "Reddit",
            "reddit.com",
            80000000,
            ["Usernames", "Email addresses", "Passwords (hashed)"],
            "ceo@example.com",
        ),
        (
            "2023-08-11",
            "Ticketmaster Data Breach",
            "Ticketmaster/Live Nation",
            "ticketmaster.com",
            560000000,
            [
                "Email addresses",
                "Credit card numbers",
                "Phone numbers",
                "Physical addresses",
            ],
            "admin@example.com",
        ),
        (
            "2024-04-22",
            "Hertz 2024 Data Leak",
            "Hertz",
            "hertz.com",
            37000000,
            ["Driver licenses", "Credit cards", "Frequent flyer data"],
            "ceo@example.com",
        ),
        (
            "2024-05-30",
            "CrowdStrike Breach",
            "CrowdStrike",
            "crowdstrike.com",
            350000,
            ["Customer emails", "Support ticket data", "Account metadata"],
            "support@google.com",
        ),
        (
            "2023-07-02",
            "X (Twitter) API Leak",
            "X (Twitter)",
            "twitter.com",
            235000000,
            ["Email addresses", "Phone numbers", "Account creation dates"],
            "admin@example.com",
        ),
        (
            "2024-06-14",
            "Uber 2024 Vendor Leak",
            "Uber",
            "uber.com",
            45000000,
            ["Phone numbers", "Email addresses", "Trip history"],
            "ceo@example.com",
        ),
        (
            "2024-07-19",
            "Dropbox Credentials Leak",
            "Dropbox",
            "dropbox.com",
            7400000,
            ["Email addresses", "Password hashes", "File metadata"],
            "admin@example.com",
        ),
        (
            "2023-09-01",
            "Adobe Subscriber Data",
            "Adobe Creative Cloud",
            "adobe.com",
            8000000,
            ["Email addresses", "Product keys", "Subscription status"],
            "support@google.com",
        ),
        (
            "2024-08-09",
            "Shopify Merchant Portal",
            "Shopify",
            "shopify.com",
            12000000,
            ["Merchant emails", "Store names", "Billing addresses"],
            "ceo@example.com",
        ),
        (
            "2023-11-25",
            "Disney+ Account Dumps",
            "Disney+",
            "disneyplus.com",
            25000000,
            ["Email addresses", "Passwords (masked)"],
            "admin@example.com",
        ),
        (
            "2024-09-03",
            "GitHub Enterprise Secrets",
            "GitHub",
            "github.com",
            4000000,
            ["Email addresses", "SSH keys", "Auth tokens"],
            "ceo@example.com",
        ),
        (
            "2023-05-17",
            "Facebook Meta Scraped",
            "Meta / Facebook",
            "facebook.com",
            533000000,
            ["Phone numbers", "Email addresses", "DOB", "Locations"],
            "admin@example.com",
        ),
    ]
    async with AsyncSessionLocal() as db:
        if force:
            await db.execute(text("TRUNCATE drp_breaches CASCADE"))
            await db.commit()
        count = 0
        for bdate, bname, title, dom, pwn, dcls, matched in breach_samples:
            exist = (
                await db.execute(
                    select(Breach).where(
                        Breach.breach_name == bname, Breach.matched_email == matched
                    )
                )
            ).scalar_one_or_none()
            if not exist:
                days_ago = random.randint(0, 29)
                created = datetime.now(timezone.utc) - timedelta(days=days_ago)
                br = Breach(
                    breach_name=bname,
                    title=title,
                    domain=dom,
                    breach_date=datetime.strptime(bdate, "%Y-%m-%d").date(),
                    pwn_count=pwn,
                    description=f"Sensitive data breach affecting {pwn:,} accounts. Compromised data: {', '.join(dcls)}",
                    data_classes=dcls,
                    matched_email=matched,
                    # Source-declared payload: the sample secret and the
                    # classification flags are not core columns.
                    attributes={
                        "masked_password": "****" if random.random() > 0.5 else "a***z",
                        "is_verified": random.random() > 0.3,
                    },
                    created_at=created,
                )
                db.add(br)
                count += 1
        await db.commit()
        return count


async def _ensure_settings() -> SystemSettings:
    async with AsyncSessionLocal() as db:
        s = (await db.execute(select(SystemSettings).limit(1))).scalar_one_or_none()
        if not s:
            s = SystemSettings()
            db.add(s)
            await db.commit()
            await db.refresh(s)
        return s


if __name__ == "__main__":
    app()
