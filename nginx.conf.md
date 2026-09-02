# /etc/nginx/snippets/sso-protect.conf

auth_request /auth;
auth_request_set $auth_status $upstream_status;

# อนุญาตให้ IP ภายในเข้าถึงได้เลยโดยไม่ต้อง Login
satisfy any;
allow 192.168.0.0/16;
allow 172.16.0.0/12;
allow 10.0.0.0/8;
deny all;

# ถ้าไม่ได้ Login ให้เด้งไปหน้า Login
error_page 401 = /rbhlogin;
error_page 403 = /rbhlogin;



# /etc/nginx/snippets/sso-endpoints.conf

location = /auth {
    internal;
    proxy_pass http://10.10.90.10:8080/verify;
    proxy_set_header Authorization $http_authorization;
    proxy_set_header Cookie $http_cookie;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    
    # ส่งข้อมูลกลับไปให้ Auth Service รู้ว่ากำลังเข้าโดเมนไหน (เผื่อใช้ในอนาคต)
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Original-Host $host;
}

location /rbhlogin {
    proxy_pass http://10.10.90.10:8080/rbhlogin;
    
    # [สำคัญ] บังคับเปลี่ยน Cookie โดเมนให้แชร์กันทุก Subdomain (*.rajburi.org)
    # หากระบบ backend ส่ง cookie domain เป็นไอพีหรือโดเมนอื่น จะถูกแปลงเป็น .rajburi.org
    proxy_cookie_domain ~^(.*)$ .rajburi.org;
    
    # ส่ง Header ไปให้ backend รู้ว่ากำลังเรียกจากโดเมนไหน
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}