# Zerotrustdns

Zerotrustdns là một **control-plane updater** cho Cloudflare Zero Trust Gateway:

1. Tải blocklist và allowlist.
2. Chuẩn hóa, lọc và deduplicate domain.
3. Đồng bộ domain vào các Gateway Lists.
4. Cập nhật một Gateway DNS rule để chặn các list đó.

Repo này **không chạy DNS resolver, DNS server hay agent trên thiết bị**. Cloudflare Gateway mới là nơi nhận truy vấn DNS và áp chính sách. Người dùng cần tự cấu hình DNS Location/DoH/DoT/IPv4 trong Cloudflare; repo chỉ cập nhật dữ liệu và rule.

## Blocklist mặc định

- [AdGuard DNS Filter](https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt)
- [hostsVN](https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts)

Allowlist mặc định lấy từ các exclusion list tương ứng của AdGuard.

## Cài đặt Cloudflare

1. Kích hoạt **Zero Trust** cho Cloudflare account.
2. Lấy **Account ID** trong Cloudflare Zero Trust.
3. Tạo API token có quyền **Account → Zero Trust → Edit**.
4. Fork repo này về GitHub account của bạn. Secrets của repo gốc không được sao chép sang fork.
5. Trong **Settings → Secrets and variables → Actions**, thêm repository secrets:
   - `CLOUDFLARE_API_TOKEN`
   - `CLOUDFLARE_ACCOUNT_ID`
6. Tùy chọn cấu hình:
   - Repository variables:
     - `CLOUDFLARE_LIST_ITEM_LIMIT` — số domain tối đa parser giữ lại, mặc định `300000`.
     - `CLOUDFLARE_LIST_ACCOUNT_LIMIT` — giới hạn tổng số Gateway Lists của toàn account, gồm cả list không do tool quản lý; mặc định `300`.
     - `CLOUDFLARE_MIN_DOMAIN_RETENTION_RATIO` — dừng nếu dữ liệu mới giảm quá mạnh; mặc định `0.5`.
     - `CLOUDFLARE_ALLOW_LARGE_SHRINK` — đặt `1` chỉ khi cố ý cho phép giảm mạnh.
   - Repository secrets:
     - `BLOCKLIST_URLS` — URL tùy chỉnh, mỗi URL một dòng.
     - `ALLOWLIST_URLS` — URL tùy chỉnh, mỗi URL một dòng.

Chỉ hai secret Cloudflare đầu tiên là bắt buộc. URL tùy chỉnh phải là `https://` và không được chứa username/password.

Một Cloudflare account chỉ nên được quản lý bởi một fork, vì tool sở hữu các tài nguyên có namespace tên `zerotrustdns`.

## Workflow GitHub

- Tự đồng bộ mỗi ngày lúc **03:00 UTC**.
- Có thể chạy thủ công từ **Actions → Update blocklists → Run workflow**; job production chỉ chạy trên branch `main`.
- Pull request và push chỉ chạy kiểm tra format, Clippy, tests và release build; các job này **không nhận Cloudflare secrets** và không gọi API Cloudflare.
- Workflow luôn chạy toàn bộ kiểm tra trước khi job production thực hiện live sync.

## Chạy local

Cần Rust toolchain **1.98.1** (được pin trong `rust-toolchain.toml`).

```bash
cp .env.example .env
# điền CLOUDFLARE_API_TOKEN và CLOUDFLARE_ACCOUNT_ID vào .env nếu chạy sync thật
cargo test --locked
cargo run --locked -- --dry       # tải và phân tích, không gọi Cloudflare API
cargo run --locked --release      # đồng bộ thật vào Cloudflare
```

`.env` là tùy chọn; biến môi trường có sẵn được ưu tiên hơn giá trị trong file. Dry-run không cần Cloudflare credentials và chỉ in số lượng domain, không in mẫu domain ra log.

## An toàn và fork isolation

- Nếu một source lỗi, timeout, redirect, quá lớn hoặc trả về tài liệu lỗi, toàn bộ run dừng trước khi đọc/ghi Cloudflare.
- Domain rỗng hoặc kết quả giảm bất thường không được phép tự động xóa coverage hiện có.
- Tool kiểm tra quota trước khi ghi, đọc lại list/rule sau mutation và có compensation khi một bước chắc chắn thất bại.
- Rule/list chỉ được nhận diện bằng tên, type và ownership marker chính xác; không đụng vào resource foreign cùng tên.
- Rule mới được xác minh trước khi xóa các list cũ; mutation có kết quả mơ hồ không bị retry mù.
- Không commit Account ID, API token hay file `.env` vào repo.

Dự án lấy cảm hứng từ [cloudflare-gateway-pihole-scripts](https://github.com/mrrfv/cloudflare-gateway-pihole-scripts) by mrrfv.
