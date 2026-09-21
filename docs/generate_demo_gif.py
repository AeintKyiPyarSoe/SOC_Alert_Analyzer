import os
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

def create_demo_gif():
    assets_dir = Path(__file__).resolve().parent / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)
    gif_path = assets_dir / "demo.gif"

    # Width and Height for GitHub README banner
    W, H = 1000, 560
    
    # Colors matching UI/UX spec
    BG_MAIN = (13, 17, 23)
    BG_SURFACE = (19, 25, 32)
    BG_SECONDARY = (24, 31, 40)
    BORDER = (41, 49, 61)
    TEXT_MAIN = (234, 240, 246)
    TEXT_MUTED = (152, 164, 181)
    TEXT_FAINT = (99, 112, 131)
    MINT = (160, 237, 197)
    CRITICAL = (255, 131, 147)
    HIGH = (245, 177, 125)
    MEDIUM = (228, 203, 132)
    LOW = (141, 203, 180)
    PURPLE_BG = (26, 22, 37)
    PURPLE_BORDER = (72, 58, 107)
    PURPLE_TEXT = (208, 188, 255)

    def draw_base_frame(title_step, highlight_tab="overview"):
        img = Image.new("RGB", (W, H), BG_MAIN)
        draw = ImageDraw.Draw(img)

        # Header
        draw.rectangle([(0, 0), (W, 48)], fill=BG_SURFACE, outline=BORDER)
        draw.text((20, 15), "🛡️ SOC Alert Analyzer", fill=TEXT_MAIN)
        draw.rectangle([(190, 14), (230, 32)], fill=BG_SECONDARY, outline=MINT)
        draw.text((198, 16), "LAB", fill=MINT)
        draw.text((245, 16), "Nicole’s Security Lab • Private workspace", fill=TEXT_MUTED)

        # Live Sensor Pill
        draw.rectangle([(630, 12), (830, 36)], fill=BG_SECONDARY, outline=BORDER)
        draw.ellipse([(642, 21), (650, 29)], fill=MINT)
        draw.text((658, 16), "HOST SENSOR: ACTIVE", fill=TEXT_MAIN)

        # Nicole Avatar
        draw.ellipse([(948, 10), (976, 38)], fill=BG_SECONDARY, outline=MINT)
        draw.text((958, 15), "N", fill=MINT)

        # Hero
        draw.text((24, 64), "Less noise. More clarity.", fill=TEXT_MAIN)
        draw.text((24, 94), "Defensive Security Operations Center — Real-time host security monitoring & triage", fill=TEXT_MUTED)

        # Buttons
        draw.rectangle([(640, 68), (810, 104)], fill=MINT)
        draw.text((655, 78), "🛡️ Scan Host Security", fill=(11, 16, 23))

        draw.rectangle([(824, 68), (920, 104)], fill=BG_SECONDARY, outline=BORDER)
        draw.text((838, 78), "🎯 Test Drill", fill=TEXT_MAIN)

        draw.rectangle([(930, 68), (976, 104)], fill=BG_SECONDARY, outline=BORDER)
        draw.text((945, 78), "...", fill=TEXT_MAIN)

        # 4 Severity Cards
        cards = [
            ("CRITICAL", "75-100", "2", "Investigate first", CRITICAL, 24),
            ("HIGH", "50-74", "3", "Review promptly", HIGH, 266),
            ("MEDIUM", "25-49", "4", "Check context", MEDIUM, 508),
            ("LOW", "0-24", "3", "Usually routine", LOW, 750)
        ]
        for name, rng, cnt, desc, col, x in cards:
            draw.rectangle([(x, 122), (x + 226, 192)], fill=BG_SURFACE, outline=BORDER)
            draw.text((x + 12, 130), name, fill=col)
            draw.text((x + 160, 130), rng, fill=TEXT_FAINT)
            draw.text((x + 12, 148), cnt, fill=TEXT_MAIN)
            draw.text((x + 48, 158), desc, fill=TEXT_MUTED)
            # progress bar
            draw.rectangle([(x + 12, 180), (x + 214, 184)], fill=BG_SECONDARY)
            draw.rectangle([(x + 12, 180), (x + 100, 184)], fill=col)

        # 2-Column Workspace
        # Left Queue (W: 460)
        draw.rectangle([(24, 210), (480, 536)], fill=BG_SURFACE, outline=BORDER)
        # Filters row
        draw.text((36, 222), "All alerts (12)", fill=MINT)
        draw.text((140, 222), "Needs review (12)", fill=TEXT_MUTED)
        draw.text((260, 222), "Reviewed (0)", fill=TEXT_MUTED)
        # Search input box
        draw.rectangle([(36, 246), (468, 274)], fill=BG_MAIN, outline=BORDER)
        draw.text((46, 252), "🔍 Search title, IP, device, technique (/)...", fill=TEXT_FAINT)

        # Queue rows
        rows = [
            ("CRITICAL", "81", "Repeated SSH login attempts", "Wazuh", "192.168.1.45", CRITICAL, True),
            ("CRITICAL", "78", "ET EXPLOIT Apache Struts RCE", "Suricata", "198.51.100.22", CRITICAL, False),
            ("HIGH", "70", "Inbound Port Scan Sweep", "Suricata", "203.0.113.42", HIGH, False),
            ("HIGH", "64", "Rootcheck: Hidden process detected", "Wazuh", "Host Sensor", HIGH, False),
            ("HIGH", "58", "Suspicious PowerShell Encoded Cmd", "Wazuh", "win-workstation-02", HIGH, False),
        ]
        ry = 286
        for sev, sc, title, src, ep, col, sel in rows:
            if sel:
                draw.rectangle([(25, ry), (479, ry + 44)], fill=BG_SECONDARY)
                draw.rectangle([(25, ry), (29, ry + 44)], fill=MINT)
            draw.rectangle([(36, ry + 6), (88, ry + 20)], outline=col)
            draw.text((40, ry + 7), sev, fill=col)
            draw.text((96, ry + 7), sc, fill=TEXT_FAINT)
            draw.text((36, ry + 24), title, fill=TEXT_MAIN)
            draw.text((320, ry + 24), f"{src} • {ep}", fill=TEXT_MUTED)
            ry += 48

        # Right Detail Panel (W: 470)
        draw.rectangle([(496, 210), (976, 536)], fill=BG_SURFACE, outline=BORDER)
        # Header inside details
        draw.rectangle([(510, 220), (570, 236)], outline=CRITICAL)
        draw.text((516, 222), "CRITICAL", fill=CRITICAL)
        draw.text((580, 222), "ID 5710", fill=TEXT_FAINT)
        draw.rectangle([(860, 218), (960, 240)], fill=BG_SECONDARY, outline=MINT)
        draw.text((870, 222), "✓ Mark reviewed", fill=MINT)

        draw.text((510, 246), "Repeated SSH login attempts", fill=TEXT_MAIN)
        draw.text((510, 268), "Sensor: Wazuh  •  Host: ubuntu-server  •  10:01:05 UTC", fill=TEXT_MUTED)

        # Tabs
        tabs = [("Overview", 510), ("Evidence", 590), ("Raw JSON", 670)]
        for tname, tx in tabs:
            if tname.lower() == highlight_tab.lower():
                draw.text((tx, 290), tname, fill=MINT)
                draw.line([(tx, 306), (tx + 55, 306)], fill=MINT, width=2)
            else:
                draw.text((tx, 290), tname, fill=TEXT_MUTED)

        # Content Card: What happened?
        draw.rectangle([(510, 316), (962, 386)], fill=BG_SECONDARY, outline=BORDER)
        draw.text((520, 324), "❓ WHAT HAPPENED?", fill=TEXT_MUTED)
        draw.text((520, 342), "Someone repeatedly tried to log in to the server via SSH using root account.", fill=TEXT_MAIN)
        draw.text((520, 360), "37 consecutive failed authentication attempts were detected from 192.168.1.45.", fill=TEXT_MUTED)

        # MITRE ATT&CK Purple Card
        draw.rectangle([(510, 394), (962, 444)], fill=PURPLE_BG, outline=PURPLE_BORDER)
        draw.text((520, 400), "MITRE ATT&CK: T1110 - Brute Force", fill=PURPLE_TEXT)
        draw.text((760, 400), "From event • unverified", fill=MINT)
        draw.text((520, 420), "Tactic: Credential Access  |  View Framework Reference ↗", fill=TEXT_MUTED)

        # Checklist
        draw.rectangle([(510, 452), (962, 524)], fill=BG_SECONDARY, outline=BORDER)
        draw.text((520, 458), "PRACTICAL DEFENSIVE PLAYBOOK", fill=TEXT_MUTED)
        draw.text((790, 458), "2 of 4 completed", fill=MINT)
        draw.text((520, 478), "[X] Check whether 192.168.1.45 is a known team workstation", fill=TEXT_FAINT)
        draw.text((520, 498), "[X] Verify SSH authentication logs to ensure no login succeeded", fill=TEXT_FAINT)

        # Step overlay banner
        draw.rectangle([(20, 520), (320, 550)], fill=(0, 0, 0))
        draw.text((24, 528), f"▶ {title_step}", fill=MINT)

        return img

    frames = [
        draw_base_frame("1. Real-Time Host EDR Dashboard", "overview"),
        draw_base_frame("2. Native Host Security Audit", "overview"),
        draw_base_frame("3. Prioritized Alert Triage & T1110 Mapping", "overview"),
        draw_base_frame("4. Interactive Playbook Checklist", "overview"),
        draw_base_frame("5. Telemetry Evidence & Raw JSON", "evidence"),
    ]

    # Save as 10-second looping GIF (2 seconds per frame = duration=2000ms)
    frames[0].save(
        gif_path,
        save_all=True,
        append_images=frames[1:],
        duration=2000,
        loop=0
    )
    print(f"[+] Successfully generated demo GIF at {gif_path}")

if __name__ == "__main__":
    create_demo_gif()
