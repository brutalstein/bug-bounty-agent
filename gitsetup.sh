#!/bin/bash
set -e

# ===== AYARLAR =====
GITHUB_USER="brutalstein"
GITHUB_EMAIL="cenkerusta@outlook.com"
REPO_NAME="bug-bounty-agent"
REPO_URL="git@github.com:${GITHUB_USER}/${REPO_NAME}.git"
SSH_KEY="$HOME/.ssh/id_ed25519"

echo "=================================================="
echo "1) Git config ayarlanıyor"
echo "=================================================="
git config --global user.name "$GITHUB_USER"
git config --global user.email "$GITHUB_EMAIL"

echo "=================================================="
echo "2) SSH key kontrol ediliyor"
echo "=================================================="
if [ ! -f "$SSH_KEY" ]; then
    echo "SSH key bulunamadı, oluşturuluyor..."
    ssh-keygen -t ed25519 -C "$GITHUB_EMAIL" -f "$SSH_KEY" -N ""
else
    echo "SSH key zaten mevcut: $SSH_KEY"
fi

eval "$(ssh-agent -s)" > /dev/null
ssh-add "$SSH_KEY"

# Eğer key GitHub'a daha önce eklenmemişse bağlantı testi başarısız olur
if ! ssh -T git@github.com 2>&1 | grep -q "successfully authenticated"; then
    echo ""
    echo "=================================================="
    echo "GITHUB'A KEY EKLEMEN GEREKİYOR"
    echo "=================================================="
    echo "Aşağıdaki public key'i kopyala:"
    echo ""
    cat "${SSH_KEY}.pub"
    echo ""
    echo "Şu adrese git ve key'i ekle:"
    echo "https://github.com/settings/ssh/new"
    echo ""
    read -p "Key'i ekledikten sonra ENTER'a bas... "

    echo "Bağlantı tekrar test ediliyor..."
    ssh -T git@github.com || true
fi

echo "=================================================="
echo "3) Repo hazırlanıyor ve push ediliyor"
echo "=================================================="

if [ ! -d ".git" ]; then
    echo "Bu klasör henüz git repo değil, init ediliyor..."
    git init
fi

git add .

if ! git diff --cached --quiet; then
    git commit -m "Initial commit"
else
    echo "Commit edilecek yeni değişiklik yok, devam ediliyor..."
fi

git branch -M main

if git remote get-url origin >/dev/null 2>&1; then
    git remote set-url origin "$REPO_URL"
else
    git remote add origin "$REPO_URL"
fi

git push -u origin main

echo ""
echo "=================================================="
echo "✅ TAMAMLANDI"
echo "Repo: https://github.com/${GITHUB_USER}/${REPO_NAME}"
echo "=================================================="