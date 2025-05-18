#!/data/data/com.termux/files/usr/bin/bash

# دریافت آدرس سایت از کاربر
read -p "لینک سایت را وارد کنید (مثلاً https://example.com): " site

echo -e "\n[+] شروع بررسی XSS ساده در پارامتر GET..."

# بارگذاری یک payload ساده XSS
payload="<script>alert('xss')</script>"

# تست روی یک پارامتر ساده مثل search
test_url="${site%/}?search=$payload"

# درخواست و بررسی وجود payload در پاسخ
response=$(curl -s "$test_url")

if echo "$response" | grep -q "$payload"; then
  echo "[!] احتمال آسیب‌پذیری XSS در: $test_url"
else
  echo "[-] XSS ساده یافت نشد."
fi

echo -e "\n[+] پایان بررسی XSS."
