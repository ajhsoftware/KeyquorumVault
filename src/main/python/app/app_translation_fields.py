"""
Keyquorum Vault
Copyright (C) 2025-2026 Anthony Hatton (AJH Software)

This file is part of Keyquorum Vault.

Keyquorum Vault is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Keyquorum Vault is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
"""

"""
Language-aware label sets used across the application for
special behaviour (password handling, platform help, email
auto-completion, autofill category gating, etc).
"""

PLATFORM_LABELS = {s.lower() for s in [
    "platform", "plataforma", "plataforma","plateforme", "plattform", "piattaforma",
    "platforma", "платформа", "platformă", "平台", "プラットフォーム", "플랫폼",
]}

INSTALL_LINK_LABELS = {s.lower() for s in [
    "install link", "installation link", "instalacionen link",
    "enlace de instalación", "lien d’installation", "инсталационен линк",
    "installationslink", "installationslänk", "асеннуслинкки",
    "kurulum bağlantısı", "installeringslenke", "link de instalação", "link de instalare",
    "instalační odkaz", "telepítési link", "asennuslinkki",
    "安装链接", "安裝連結", "インストールリンク", "설치 링크",
]}

EMAIL_LABELS = {s.lower() for s in [
    "email", "mail", "e-mail", 
    "correo electrónico",                            # ES 
    "e-mail-adresse",                                # DE
    "courriel", "adresse e-mail",                    # FR
    "почта",
    "indirizzo email",                               # IT
    "e-post", 
    "e-posta", 
    "élőimél", 
    "e-mail cím",                                     # HU
    "e-mailadres", 
    "e-mailová adresa", 
    "електронна поща",                               # BG
    "邮箱", "電子郵件",                                # ZH
    "电邮", "电子邮件", 
    "メールアドレス", "电子郵件",  
    "メール",                                          # JA
    "이메일",                                          # KO
    "адрес эл. почты",                                # RU
    "имейл", 
    "эл. почта",
]}             

PRIMARY_PASSWORD_LABELS = {s.lower() for s in [
    "password",                             # English 
    "passwort",                             # German
    "mot de passe",                         # French
    "hasło",                                # Polish 
    "senha",                                # Portuguese (Brazil) 
    "contraseña",                           # Spanish
    "wachtwoord",                           # Dutch
    "heslo",                                # Czech 
    "salasana",                             # Finnish 
    "adgangskode",                          # Danish / Norwegian 
    "lösenord",                             # Swedish
    "parolă",                               # Romanian
    "şifre",                                # Turkish
    "пароль",                               # Russian
    "парола",                               # Bulgarian 
    "密码",                                  # Chinese (Simplified) 
    "密碼",                                  # Chinese (Traditional) 
    "パスワード",                             # Japanese 
    "비밀번호",                               # Korean
]}

AUTOFILL_ALLOWED_CATEGORY_LABELS = {
    s.lower() for s in [
        # Games
        "games", "game", "juegos", "jeux", "spiele", "giochi", "gry",
        "игри", "игры", "spel", "spill", "pelit", "hry", "játékok", "ゲーム",
        "게임", "游戏", "遊戲",

        # Social
        "social", "social media", "redes sociales", "réseaux sociaux",
        "soziale netzwerke", "sociale media", "socialt nätverk",
        "социальные сети", "социални мрежи", "소셜 미디어", "ソーシャル メディア",

        # Streaming
        "stream", "streaming", "transmisión", "diffusion en continu",
        "streamingdienst", "transmisie", "스트리밍", "ストリーミング", "串流", "流媒体",

        # Apps / Software
        "app", "apps", "application", "applications", "aplicación",
        "aplicaciones", "anwendung", "anwendungen", "applicazione",
        "applicazioni", "aplicativo", "aplicativos", "software",
        "oprogramowanie", "软件", "軟件", "ソフトウェア", "소프트웨어",
    ]
}

USERNAME_HEADER_LABELS = {s.lower() for s in [
    "username", "user name",
    "nombre de usuario",          # ES
    "benutzername",               # DE
    "nom d’utilisateur",          # FR
    "nome utente",                # IT
    "nome de usuário", "nome de utilizador",  # PT
    "nazwa użytkownika",          # PL
    "имя пользователя",           # RU
    "потребителско име",          # BG
    "用户名", "使用者名稱",          # ZH
    "ユーザー名",                    # JA
    "사용자 이름",                  # KO
]}

def _canonical_header_role(text: str | None) -> str | None:
    """Map a localized column header to a canonical role."""
    t = (text or "").strip().lower()
    if not t:
        return None
    if t in USERNAME_HEADER_LABELS:
        return "username"
    if t in EMAIL_LABELS:
        return "email"
    if ("pass" in t) or (t in PRIMARY_PASSWORD_LABELS):
        return "password"
    return None

def _is_password_header(text: str | None) -> bool:
    t = (text or "").strip().lower()
    return "pass" in t or t in PRIMARY_PASSWORD_LABELS

def _entry_value_by_labelset(entry: dict, label_set: set[str]) -> str:
    """
    Get a value from an entry dict by matching ANY of the translated labels
    in label_set (case-insensitive).
    """
    if not entry:
        return ""
    low = {str(k).strip().lower(): v for k, v in entry.items()}
    for lab in label_set:
        v = low.get(lab)
        if v:
            return str(v).strip()
    return ""


