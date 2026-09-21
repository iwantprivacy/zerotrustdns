# Zerotrustdns

Zerotrustdns là một **control-plane updater** cho Cloudflare Zero Trust Gateway:

1. Tải blocklist và allowlist.
2. Lọc, chuẩn hóa, deduplicate domain.
3. Đồng bộ domain vào các Gateway Lists.
4. Cập nhật một Gateway DNS rule để chặn các list đó.

Repo này **không chạy DNS resolver, DNS server hay agent trên thiết bị**. Cloudflare
Gateway mới là nơi nhận truy vấn DNS và áp chính sách. Người dùng cần tự cấu hình
DNS Location/DoH/DoT/IPv4 trong Cloudflare; repo chỉ cập nhật dữ liệu và rule.

## Blocklist mặc định

- [AdGuard DNS Filter](https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt)
- [hostsVN](https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts)

Allowlist mặc định lấy từ các exclusion list tương ứng của AdGuard.

## Cài đặt

### 1. Chuẩn bị Cloudflare

- Kích hoạt **Zero Trust** cho Cloudflare account.
- Lấy **Account ID** trong Cloudflare Zero Trust.
- Tạo API token có quyền **Account → Zero Trust → Edit**.

### 2. Fork repo

Fork repo này về GitHub account của bạn. Secrets của repo gốc không được sao chép
sang fork.

Một Cloudflare account chỉ nên được quản lý bởi một fork, vì tool sở hữu các tài
nguyên có namespace tên `zerotrustdns`.

### 3. Thêm secrets

Trong fork, vào **Settings → Secrets and variables → Actions** và thêm:

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`

Có thể cấu hình thêm:

- `CLOUDFLARE_LIST_ITEM_LIMIT` — số domain tối đa mà parser giữ lại, mặc định `300000`.
- `CLOUDFLARE_LIST_ACCOUNT_LIMIT` — giới hạn tổng số Gateway Lists của toàn account,
  bao gồm cả list không do tool quản lý, mặc định `300`.
- `CLOUDFLARE_MIN_DOMAIN_RETENTION_RATIO` — dừng nếu dữ liệu mới giảm quá mạnh,
  mặc định `0.5`.
- `CLOUDFLARE_ALLOW_LARGE_SHRINK` — đặt `1` chỉ khi cố ý cho phép giảm mạnh.
- `BLOCKLIST_URLS` — URL blocklist tùy chỉnh, mỗi URL một dòng.
- `ALLOWLIST_URLS` — URL allowlist tùy chỉnh, mỗi URL một dòng.

Chỉ hai secret Cloudflare đầu tiên là bắt buộc. URL tùy chỉnh phải là `https://`
và không được chứa username/password.

### 4. Chạy workflow

Vào **Actions → Update blocklists → Run workflow** và chọn branch `main`.
Workflow cũng tự chạy mỗi ngày lúc **03:00 UTC**.

## Chạy local

Node.js `20.12+` là bắt buộc.

```bash
cp .env.example .env
# điền CLOUDFLARE_API_TOKEN và CLOUDFLARE_ACCOUNT_ID vào .env
npm ci
npm test
npm run dry       # tải và phân tích, không gọi Cloudflare API
npm start         # đồng bộ thật vào Cloudflare
```

`npm run dry` không cần Cloudflare credentials và chỉ in số lượng domain, không in
mẫu domain ra log.

## An toàn và fork isolation

- Nếu một source lỗi, timeout, redirect, quá lớn hoặc trả về tài liệu lỗi, toàn bộ
  run dừng trước khi đọc/ghi Cloudflare.
- Domain rỗng hoặc kết quả giảm bất thường không được phép tự động xóa toàn bộ
  coverage hiện có.
- Tool lập kế hoạch quota trước khi ghi, đọc lại list/rule sau mutation và có
  compensation khi một bước chắc chắn thất bại.
- Rule/list chỉ được nhận diện bằng tên, type và ownership marker chính xác; không
  đụng vào resource foreign cùng tên.
- Không commit Account ID, API token hay file `.env` vào repo.

Dự án lấy cảm hứng từ
[cloudflare-gateway-pihole-scripts](https://github.com/mrrfv/cloudflare-gateway-pihole-scripts)
by mrrfv.
