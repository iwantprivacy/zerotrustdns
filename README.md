# Zerotrustdns

Chặn quảng cáo ở cấp DNS bằng Cloudflare Zero Trust Gateway — miễn phí, không cần cài app hay extension; có thể thêm các blocklist tùy chọn.

Mặc định project được cấu hình theo policy của project cho tối đa 300 Lists ×
1.000 entry mỗi List, tức khoảng 300.000 domain. Đây không phải cam kết quota
chung cho mọi Cloudflare account; nếu account có quota thấp hơn hoặc đã dùng
Lists cho mục đích khác, hãy giảm các biến giới hạn. Chương trình lập kế hoạch
trước khi ghi, nhưng các thao tác provider vẫn có thể cần compensation nếu một
request giữa chừng thất bại.

> **Fork-friendly:** repo này không chứa Account ID, API token hay tài nguyên
> Cloudflare của tác giả. Mỗi người fork cần cấu hình credentials của **chính
> tài khoản Cloudflare của mình** trong fork đó; không commit credentials vào
> code hoặc file `.env`.
>
> Một Cloudflare account chỉ nên được quản lý bởi một fork của project này,
> vì các list/rule do tool sở hữu được nhận diện bằng namespace tên
> `zerotrustdns`.

## Cách hoạt động

1. Tải danh sách domain cần chặn từ internet
2. Lọc và loại bỏ trùng lặp, loại bỏ các domain được cho phép
3. Upload lên Cloudflare Gateway dưới dạng "Lists"
4. Tạo Gateway DNS policy chặn toàn bộ các domain trong danh sách
5. Tự cập nhật mỗi ngày theo lịch GitHub Actions (03:00 UTC; GitHub có thể trì hoãn job)

## Blocklist mặc định

- **AdGuard DNS Filter** — chặn quảng cáo
- **hostsVN** — chặn quảng cáo Việt Nam


## Cài đặt

### Bước 1 — Kích hoạt Zero Trust

- Vào [one.dash.cloudflare.com](https://one.dash.cloudflare.com) và đăng nhập
- Làm theo hướng dẫn để kích hoạt gói Zero Trust Free

### Bước 2 — Tạo DNS Location

1. Vào [dash.cloudflare.com](https://dash.cloudflare.com) → sidebar trái chọn **Zero Trust**
2. Vào **Networks → Resolvers & Proxies** → chọn **Add a location**
3. Điền **Location name** tùy thích, bật các endpoint tùy nhu cầu:
   - **IPv4 DNS** — gán IP thẳng vào router/modem nhà mạng
   - **DNS over TLS (DoT)** — gán vào thiết bị Android
   - **DNS over HTTPS (DoH)** — gán vào iPhone/iPad hay trình duyệt máy tính
4. Nên bật thêm **Enable EDNS client subnet** (ECS ẩn danh trong nước) và **Set as Default DNS Location**
5. Ấn **Continue** → **Continue** lần nữa là xong
6. Hệ thống sẽ hiển thị thông số DNS (IPv4, DoT, DoH), bạn gán vào thiết bị theo hướng dẫn

### Bước 3 — Lấy API Token + Account ID

**Account ID:**
- Ở bước 2 bạn đang ở Zero Trust, kéo lên chọn **Overview** — Account ID nằm ở bên phải trang, copy nó

**API Token:**
- Vào [dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens)
- Bấm **Create Token → Create Custom Token**
- Đặt tên tùy ý
- Mục **Permissions** chọn: **Account** giữ nguyên, ở giữa chọn `Zero Trust`, ở ngoài chọn `Edit`
- Bấm **Continue to summary → Create Token**
- Copy token lại (chỉ hiện 1 lần duy nhất)

### Bước 4 — Fork repo

Bấm **Fork → Create fork** ở góc trên bên phải.

> Khi fork, GitHub không sao chép Actions secrets của repo gốc. Workflow trong
> fork cũng có thể bị tắt mặc định; hãy vào tab **Actions** và bật workflow
> trước khi chạy.

### Bước 5 — Thêm secrets vào repo

Vào repo vừa fork → **Settings → Secrets and variables → Actions → New repository secret**

Thêm lần lượt 2 secret:
- `CLOUDFLARE_API_TOKEN` — dán API Token vừa tạo ở Bước 3
- `CLOUDFLARE_ACCOUNT_ID` — dán Account ID vừa copy ở Bước 3

Các cấu hình tùy chọn:
- Repository variable `CLOUDFLARE_LIST_ITEM_LIMIT` — giới hạn số domain, mặc định `300000`
- Repository variable `CLOUDFLARE_LIST_ACCOUNT_LIMIT` — tổng số Lists dành cho project, mặc định `300`
- Repository variable `CLOUDFLARE_MIN_DOMAIN_RETENTION_RATIO` — dừng nếu số domain mới thấp hơn tỷ lệ này so với trạng thái hiện tại, mặc định `0.5`
- Repository variable `CLOUDFLARE_ALLOW_LARGE_SHRINK` — đặt `1` nếu cố ý chấp nhận giảm blocklist mạnh, mặc định `0`
- Repository variable `BLOCK_PAGE_ENABLED` — đặt `1` để bật block page, mặc định `0`
- Secret `BLOCKLIST_URLS` — các URL blocklist tùy chỉnh, mỗi URL một dòng; để trống để dùng danh sách mặc định
- Secret `ALLOWLIST_URLS` — các URL allowlist tùy chỉnh, mỗi URL một dòng; để trống để dùng danh sách mặc định

Chỉ cần hai secret bắt buộc là fork có thể chạy với cấu hình mặc định. Không
có giá trị nào trong code tự trỏ vào tài khoản Cloudflare của repo gốc.

Mỗi URL tùy chỉnh phải là `https://` và không được chứa username/password.
Nếu một blocklist hoặc allowlist source bị lỗi, chương trình sẽ dừng trước khi
đọc hoặc thay đổi Cloudflare để tránh đồng bộ một danh sách bị thiếu.

### Bước 6 — Chạy workflow

Vào tab **Actions → Update blocklists → Run workflow** và chọn branch `main`.
Workflow chỉ cho phép chạy trên `main`.

Chờ workflow hoàn tất. Sau đó blocklist sẽ tự cập nhật theo lịch hằng ngày.

Nếu account có bật required reviewers cho environment `production`, GitHub sẽ
chờ phê duyệt trước khi cấp quyền chạy job đồng bộ.

## Chạy local

Node.js `20.12+` là bắt buộc vì project dùng `process.loadEnvFile()`.

```bash
cp .env.example .env
# điền CLOUDFLARE_API_TOKEN và CLOUDFLARE_ACCOUNT_ID của bạn vào .env
npm ci
npm test
npm run dry       # xem trước, không gọi Cloudflare API
npm start         # đồng bộ thật vào tài khoản Cloudflare của bạn
```

`npm run dry` không cần credentials Cloudflare và chỉ in số lượng domain, không
in các domain mẫu để tránh làm lộ dữ liệu từ source riêng. Nếu chạm giới hạn
item, lệnh sẽ cảnh báo số candidate không được đồng bộ. Lệnh `npm start` và
`npm run delete` chỉ được chạy sau khi đã cấu hình credentials của tài khoản
riêng; `npm run delete` là thao tác xóa các list/rule có tên chính xác do
`zerotrustdns` quản lý. `--dry` và `--delete` không được dùng cùng nhau; option
không được nhận diện cũng sẽ làm chương trình dừng thay vì chạy mode mặc định.

## Cấu hình DNS trên thiết bị

Sau khi chạy workflow xong, vào **Zero Trust → Networks → Resolvers & Proxies** → copy địa chỉ DNS (IPv4, DoT, DoH) rồi cấu hình trên thiết bị:

### iPhone/iPad

1. Copy địa chỉ DoH từ Cloudflare (dạng `https://xxxxx.cloudflare-gateway.com/dns-query`)
2. Tạo hoặc cài một DNS configuration profile dùng địa chỉ DoH đó bằng công cụ/profile manager bạn tin cậy
3. Mở file profile → **Install** → Xong

### Android

1. Copy địa chỉ DoT từ Cloudflare
2. Vào **Settings → Network → Private DNS**
3. Nhập hostname DoT → Lưu

### Router/Modem

1. Copy địa chỉ IPv4 từ Cloudflare
2. Vào cài đặt router → đổi DNS server thành địa chỉ IPv4
3. Tất cả thiết bị trong mạng sẽ tự động được chặn quảng cáo

---

Dự án lấy cảm hứng từ [cloudflare-gateway-pihole-scripts](https://github.com/mrrfv/cloudflare-gateway-pihole-scripts) by mrrfv.
