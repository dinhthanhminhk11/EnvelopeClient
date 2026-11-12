# Ghép doodleart-core và API vào app iOS (đã gộp)

Nội dung file này đã gộp vào [`../../server/docs/client-api.md`](../../server/docs/client-api.md) ngày 07/11/2026: tài liệu API duy
nhất cho team iOS / Android, gồm cả phần ghép core. Không viết thêm vào đây. Bản cũ (chi tiết theo code iOS ở `c16cfb1`, đã được đội
iOS port ở `7717454`) còn trong lịch sử git (`git show 3aa54ed:doodleart-core/docs/ios-integration.md`).

| Mục cũ ở đây | Ở `client-api.md` |
|---|---|
| 0-1. Tóm tắt, team server gửi gì | 0.4, 3.1, 3.2 |
| 2-3. Gắn thư viện vào Xcode, lớp Swift mẫu | 3.2 |
| 4.1-4.2. `APIPath`, `APIClient`, các chỗ khác trong app | 0.1, 3.2, 5 |
| 4.3. Đăng nhập Apple / Google, xoá tài khoản | 6.6-6.10 |
| 4.4. Catalog, nét vẽ, nhạc trên `/api/v2` | 7.3-7.5 |
| 5. API (đăng ký, handshake, request sealed, danh sách) | 0.3, 4, 5, 6, 7 |
| 6. Mã lỗi, status của core | 9, 10.4 |
| 7. Trust, App Attest, risk flag | 2.4 |
| 8. Thử với server dev qua ngrok | 10 |
| 9. Checklist | 11 |
| 10. Chưa có | 12 |
