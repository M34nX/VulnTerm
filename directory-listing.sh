#!/data/data/com.termux/files/usr/bin/bash

read -p "لینک سایت را وارد کنید (مثلاً https://example.com): " site

echo -e "\n[+] بررسی لیست‌ شدن مسیرها (Directory Listing)..."

dirs=( / /admin/ /uploads/ /files/ /backup/ )

for dir in "${dirs[@]}"
do
  url="${site%/}$dir"  # حذف / اضافی قبل از الحاق مسیر
  code=$(curl -s -o /dev/null -w "%{http_code}" "$url")

  if [ "$code" = "200" ]; then
    echo "[!] مسیر لیست شده پیدا شد: $url"
  fi
done

echo -e "\n[+] بررسی لیست شدن مسیرها تمام شد."
