# Tài liệu chuẩn nhóm quyền OSDU và kịch bản phân quyền người dùng

**Phiên bản:** 1.0  
**Partition tham chiếu:** `osdu`  
**Hậu tố group:** `@osdu.group`  
**Phạm vi:** nhóm quyền Entitlements phục vụ quản trị truy cập dữ liệu, gọi dịch vụ OSDU và vận hành Access Governance.

---

## 1. Mục đích tài liệu

Tài liệu này chuẩn hóa cách hiểu và cách sử dụng các nhóm quyền trong OSDU Entitlements. Nội dung tập trung vào:

- Phân loại các nhóm quyền theo vai trò trong cơ chế phân quyền OSDU.
- Danh mục nhóm quyền hiện có trong môi trường `osdu`.
- Bộ group tiêu chuẩn cho các loại người dùng và service account đặc thù.
- Nguyên tắc thiết kế phân quyền theo dữ liệu, domain, service và nghiệp vụ quản trị.
- Khuyến nghị loại bỏ quyền dư thừa và hạn chế cấp quyền admin/root.

Tổng danh sách ban đầu có **86 group**, trong đó có **01 group dùng cho kiểm thử**:

```text
data.test46.owners@osdu.group
```

Group kiểm thử này không được tính vào danh mục production. Vì vậy, danh mục production trong tài liệu gồm **85 group**.

---

## 2. Nguyên tắc phân quyền OSDU

OSDU không phân quyền chỉ bằng một role duy nhất. Một request hợp lệ thường phải đi qua các lớp kiểm tra sau:

```text
Access Token hợp lệ
+ data-partition-id đúng
+ user/service account thuộc partition tương ứng
+ có service group để gọi API
+ có data group khớp với ACL viewers/owners của record
+ legal tag compliant
+ policy/OPA cho phép
```

### 2.1. Vai trò của từng loại group

| Loại group | Mục đích | Ví dụ |
|---|---|---|
| `USER` | Xác định nhóm người dùng, vai trò nghiệp vụ hoặc quyền nền của partition | `users@osdu.group`, `users.datalake.viewers@osdu.group` |
| `SERVICE` | Cho phép gọi một OSDU service cụ thể | `service.search.user@osdu.group`, `service.storage.viewer@osdu.group` |
| `DATA` | Gắn vào `acl.viewers` hoặc `acl.owners` của record để kiểm soát dữ liệu | `data.default.viewers@osdu.group` |
| `SYSTEM` | Nhóm hệ thống phục vụ pubsub, cron hoặc tác vụ nền | `notification.pubsub@osdu.group` |

### 2.2. Quy tắc nhận diện group type

Nên chuẩn hóa rule phân loại group trong UI/API như sau:

```text
data.*                         -> DATA
service.*                      -> SERVICE
users.*                        -> USER
users@<partition>.group         -> USER
notification.*                 -> SYSTEM
partition.*                    -> SYSTEM
cron.*                         -> SYSTEM
không khớp rule                -> UNKNOWN
```

Do đó, group nền:

```text
users@osdu.group
```

phải được hiển thị là `USER`, không phải `UNKNOWN`.

### 2.3. Phân biệt service group và data group

Service group trả lời câu hỏi:

```text
Người gọi có được gọi API này không?
```

Data group trả lời câu hỏi:

```text
Người gọi có được đọc/sửa record này không?
```

Ví dụ user có `data.default.viewers@osdu.group` nhưng thiếu `service.search.user@osdu.group` thì vẫn không thể gọi Search API. Ngược lại, user có `service.search.user@osdu.group` nhưng không thuộc group trong `acl.viewers` của record thì không thấy record tương ứng.

### 2.4. Group nền partition

Trong môi trường này, group:

```text
users@osdu.group
```

đóng vai trò group nền xác nhận user thuộc datalake/partition `osdu`. Các bộ quyền người dùng thông thường nên bao gồm group này.

---

## 3. Thống kê danh mục group production

| Loại group | Số lượng |
|---|---:|
| DATA | 5 |
| SERVICE | 68 |
| USER | 9 |
| SYSTEM | 3 |
| Tổng production | 85 |

Group kiểm thử không tính vào production:

| Group | Loại | Ghi chú |
|---|---|---|
| `data.test46.owners@osdu.group` | DATA | Không sử dụng cho phân quyền production |

---

## 4. Danh mục group production

### 4.1. DATA groups

DATA group được sử dụng trong `acl.viewers` và `acl.owners` của record. Đây là lớp phân quyền trực tiếp trên dữ liệu.

| STT | Group | Loại | Mục đích sử dụng | Mức rủi ro |
|---:|---|---|---|---|
| 1 | `data.default.owners@osdu.group` | DATA | Nhóm owner của record có ACL owners chứa group này. | Cao |
| 2 | `data.default.viewers@osdu.group` | DATA | Nhóm được xem các record có ACL viewers chứa group này. | Thấp |
| 3 | `data.ihs.viewers@osdu.group` | DATA | Nhóm được xem dữ liệu IHS nếu ACL record chứa group này. | Thấp |
| 4 | `data.wke.owners@osdu.group` | DATA | Nhóm owner cho dữ liệu WKE. | Cao |
| 5 | `data.wke.viewers@osdu.group` | DATA | Nhóm được xem dữ liệu WKE nếu ACL record chứa group này. | Thấp |

### 4.2. USER groups

USER group dùng để gom người dùng theo vai trò nghiệp vụ, vai trò vận hành hoặc quyền nền của partition.

| STT | Group | Loại | Mục đích sử dụng | Mức rủi ro |
|---:|---|---|---|---|
| 1 | `users.data.root@osdu.group` | USER | Nhóm root users của datalake. | Rất cao |
| 2 | `users.datalake.admins@osdu.group` | USER | Nhóm quản trị nghiệp vụ của datalake. | Cao |
| 3 | `users.datalake.delegation@osdu.group` | USER | Nhóm user có thể impersonate user khác. | Rất cao |
| 4 | `users.datalake.editors@osdu.group` | USER | Nhóm editor nghiệp vụ của datalake. | Trung bình |
| 5 | `users.datalake.impersonation@osdu.group` | USER | Nhóm user có thể bị impersonate trong cơ chế delegation/impersonation. | Cao |
| 6 | `users.datalake.ops@osdu.group` | USER | Nhóm vận hành datalake. | Cao |
| 7 | `users.datalake.viewers@osdu.group` | USER | Nhóm viewer nghiệp vụ của datalake. | Thấp |
| 8 | `users.wellbore-data.viewers@osdu.group` | USER | Nhóm viewer nghiệp vụ Wellbore; cần data group trong ACL để enforce ở record. | Thấp |
| 9 | `users@osdu.group` | USER | Group nền xác nhận user thuộc datalake/partition `osdu`. | Thấp |

### 4.3. SERVICE groups

SERVICE group dùng để cấp quyền gọi API/service trong OSDU.

| STT | Group | Loại | Mục đích sử dụng | Mức rủi ro |
|---:|---|---|---|---|
| 1 | `service.attribute_catalog.viewers@osdu.group` | SERVICE | Xem Attribute Catalog. | Thấp |
| 2 | `service.content-extractor.user@osdu.group` | SERVICE | Sử dụng Content Extractor. | Thấp |
| 3 | `service.copyservice.admin@osdu.group` | SERVICE | Quản trị Copy Service. | Cao |
| 4 | `service.csvparser.admin@osdu.group` | SERVICE | Quản trị CSV Parser. | Cao |
| 5 | `service.datalakerecordloader.admin@osdu.group` | SERVICE | Quản trị Datalake Record Loader. | Cao |
| 6 | `service.dataset.editors@osdu.group` | SERVICE | Tạo hoặc cập nhật dataset metadata qua Dataset Service. | Cao |
| 7 | `service.dataset.viewers@osdu.group` | SERVICE | Xem dataset metadata qua Dataset Service. | Thấp |
| 8 | `service.delivery.viewer@osdu.group` | SERVICE | Xem Delivery Service. | Thấp |
| 9 | `service.document.viewer@osdu.group` | SERVICE | Xem Document Service. | Thấp |
| 10 | `service.edsdms.user@osdu.group` | SERVICE | Sử dụng hoặc chỉnh sửa EDS-DMS theo cấu hình service. | Trung bình |
| 11 | `service.entitlements.admin@osdu.group` | SERVICE | Quản trị Entitlements: tạo group, thêm/xóa member, quản lý membership. | Rất cao |
| 12 | `service.entitlements.user@osdu.group` | SERVICE | Đọc hoặc kiểm tra group membership qua Entitlements API. | Thấp |
| 13 | `service.equipmentlasparser.admin@osdu.group` | SERVICE | Quản trị Equipment LAS Parser. | Cao |
| 14 | `service.fetch.editors@osdu.group` | SERVICE | Quyền editor cho Fetch Service. | Trung bình |
| 15 | `service.fetch.viewers@osdu.group` | SERVICE | Xem Fetch Service. | Thấp |
| 16 | `service.file.editors@osdu.group` | SERVICE | Tạo, cập nhật hoặc quản lý file metadata qua File service. | Cao |
| 17 | `service.file.viewers@osdu.group` | SERVICE | Đọc hoặc tải file qua File Service tùy cấu hình API. | Thấp |
| 18 | `service.form-extractor.user@osdu.group` | SERVICE | Sử dụng Form Extractor. | Thấp |
| 19 | `service.geosiris.admin@osdu.group` | SERVICE | Quản trị Geosiris service/integration. | Cao |
| 20 | `service.gis-dl-ingestion.user@osdu.group` | SERVICE | Sử dụng dịch vụ GIS Data Lake Ingestion. | Trung bình |
| 21 | `service.gis-dl-transformation.user@osdu.group` | SERVICE | Sử dụng dịch vụ chuyển đổi dữ liệu GIS Data Lake. | Trung bình |
| 22 | `service.image-classification-classify.user@osdu.group` | SERVICE | Sử dụng dịch vụ phân loại ảnh ở chế độ classify. | Thấp |
| 23 | `service.image-classification-train.user@osdu.group` | SERVICE | Sử dụng dịch vụ huấn luyện image classification. | Trung bình |
| 24 | `service.index-document.user@osdu.group` | SERVICE | Gọi Index Document Service. | Trung bình |
| 25 | `service.ingestion.editors@osdu.group` | SERVICE | Quyền editor cho Ingestion Service. | Cao |
| 26 | `service.ingestionpipeline.admin@osdu.group` | SERVICE | Quản trị Ingestion Pipeline. | Cao |
| 27 | `service.it-mdm.admins@osdu.group` | SERVICE | Quản trị IT MDM. | Cao |
| 28 | `service.jsoningestor.admin@osdu.group` | SERVICE | Quản trị JSON Ingestor; thường dùng cho pipeline hoặc quản trị viên ingestion dạng JSON. | Cao |
| 29 | `service.lasparser.admin@osdu.group` | SERVICE | Quản trị LAS Parser. | Cao |
| 30 | `service.legal.admin@osdu.group` | SERVICE | Quản trị Legal Service. | Rất cao |
| 31 | `service.legal.editor@osdu.group` | SERVICE | Tạo hoặc chỉnh sửa Legal Tag. | Cao |
| 32 | `service.legal.user@osdu.group` | SERVICE | Gọi Legal Service ở mức user. | Thấp |
| 33 | `service.logstore.admin@osdu.group` | SERVICE | Quản trị Logstore. | Cao |
| 34 | `service.logstore.creator@osdu.group` | SERVICE | Tạo logstore hoặc đối tượng liên quan đến logstore. | Trung bình |
| 35 | `service.logstore.viewer@osdu.group` | SERVICE | Xem Logstore. | Thấp |
| 36 | `service.merge.editor@osdu.group` | SERVICE | Quyền chỉnh sửa trên Merge Service. | Cao |
| 37 | `service.merge.viewer@osdu.group` | SERVICE | Xem thông tin từ Merge Service. | Thấp |
| 38 | `service.messaging.admin@osdu.group` | SERVICE | Quản trị Messaging Service. | Cao |
| 39 | `service.messaging.user@osdu.group` | SERVICE | Gọi Messaging Service ở mức user. | Trung bình |
| 40 | `service.partition.admin@osdu.group` | SERVICE | Quản trị Partition Service. | Rất cao |
| 41 | `service.plugin.admin@osdu.group` | SERVICE | Quản trị Plugin Manager. | Cao |
| 42 | `service.plugin.user@osdu.group` | SERVICE | Sử dụng Plugin Manager ở mức user. | Thấp |
| 43 | `service.policy.admin@osdu.group` | SERVICE | Quản trị Policy Service/OPA/Rego policy. | Rất cao |
| 44 | `service.policy.user@osdu.group` | SERVICE | Gọi Policy Service để validate policy/OPA. | Thấp |
| 45 | `service.register.editor@osdu.group` | SERVICE | Quyền chỉnh sửa trên Register service. | Trung bình |
| 46 | `service.register.user@osdu.group` | SERVICE | Gọi Register Service ở mức user. | Thấp |
| 47 | `service.reservoir-dms.owners@osdu.group` | SERVICE | Quyền owner/ghi đối với Reservoir DMS. | Cao |
| 48 | `service.reservoir-dms.viewers@osdu.group` | SERVICE | Xem Reservoir DMS. | Thấp |
| 49 | `service.schema-service.admin@osdu.group` | SERVICE | Quản trị Schema Service. | Rất cao |
| 50 | `service.schema-service.editors@osdu.group` | SERVICE | Tạo hoặc chỉnh sửa schema qua Schema Service. | Cao |
| 51 | `service.schema-service.system-admin@osdu.group` | SERVICE | Quản trị system endpoints của Schema Service. | Rất cao |
| 52 | `service.schema-service.viewers@osdu.group` | SERVICE | Đọc schema/kind qua Schema Service. | Thấp |
| 53 | `service.search.admin@osdu.group` | SERVICE | Quản trị Search Service. | Cao |
| 54 | `service.search.user@osdu.group` | SERVICE | Gọi Search API để tìm kiếm record. | Thấp |
| 55 | `service.secret.admin@osdu.group` | SERVICE | Quản trị Secret Service. | Rất cao |
| 56 | `service.secret.editor@osdu.group` | SERVICE | Tạo hoặc chỉnh sửa secret. | Rất cao |
| 57 | `service.secret.viewer@osdu.group` | SERVICE | Xem Secret Service theo cấu hình bảo mật. | Cao |
| 58 | `service.seistore.admin@osdu.group` | SERVICE | Quản trị Seistore hoặc dịch vụ lưu trữ địa chấn tương ứng. | Cao |
| 59 | `service.shapeingestor.admins@osdu.group` | SERVICE | Quản trị Shape Ingestor. | Cao |
| 60 | `service.storage.admin@osdu.group` | SERVICE | Quản trị Storage Service và các thao tác quản trị record. | Rất cao |
| 61 | `service.storage.creator@osdu.group` | SERVICE | Tạo record qua Storage Service. | Cao |
| 62 | `service.storage.viewer@osdu.group` | SERVICE | Đọc record detail qua Storage Service. | Thấp |
| 63 | `service.unzipingestion.admin@osdu.group` | SERVICE | Quản trị luồng Unzip Ingestion. | Cao |
| 64 | `service.workflow.admin@osdu.group` | SERVICE | Quản trị Workflow Service. | Cao |
| 65 | `service.workflow.creator@osdu.group` | SERVICE | Tạo hoặc chạy workflow. | Cao |
| 66 | `service.workflow.system-admin@osdu.group` | SERVICE | Quản trị system endpoints của Workflow Service. | Rất cao |
| 67 | `service.workflow.viewer@osdu.group` | SERVICE | Xem workflow hoặc trạng thái workflow. | Thấp |
| 68 | `service.xlsingestor.admin@osdu.group` | SERVICE | Quản trị XLS Ingestor. | Cao |

### 4.4. SYSTEM groups

SYSTEM group phục vụ các luồng nội bộ như PubSub, partition event hoặc cron jobs. Không nên cấp thủ công cho user nghiệp vụ nếu không có yêu cầu vận hành rõ ràng.

| STT | Group | Loại | Mục đích sử dụng | Mức rủi ro |
|---:|---|---|---|---|
| 1 | `cron.job@osdu.group` | SYSTEM | Nhóm hệ thống phục vụ cron jobs. | Hệ thống |
| 2 | `notification.pubsub@osdu.group` | SYSTEM | Nhóm hệ thống phục vụ Notification PubSub. | Hệ thống |
| 3 | `partition.pubsub@osdu.group` | SYSTEM | Nhóm hệ thống phục vụ Partition PubSub. | Hệ thống |

---

## 5. Bộ group tiêu chuẩn theo loại user/service account

Các bộ group dưới đây là baseline khuyến nghị. Khi áp dụng thực tế, cần thay `data.<scope>.*` bằng data group đúng với ACL record của domain, block, project hoặc data room tương ứng.

### 5.1. Người dùng chỉ xem Data Catalog, Search và Record Detail

Dùng cho người dùng nghiệp vụ chỉ cần tìm kiếm record, mở record detail và xem thông tin governance cơ bản.

```text
users@osdu.group
users.datalake.viewers@osdu.group

data.default.viewers@osdu.group
# hoặc data.<scope>.viewers@osdu.group nếu record đã phân quyền theo scope

service.search.user@osdu.group
service.storage.viewer@osdu.group
service.legal.user@osdu.group
service.policy.user@osdu.group
```


Bổ sung khi cần tải file hoặc xem dataset:

```text
service.file.viewers@osdu.group
service.dataset.viewers@osdu.group
```

Bổ sung khi UI cần kiểm tra group membership:

```text
service.entitlements.user@osdu.group
```

Không nên cấp cho viewer thông thường:

```text
data.default.owners@osdu.group
service.storage.creator@osdu.group
service.storage.admin@osdu.group
service.entitlements.admin@osdu.group
users.data.root@osdu.group
```

### 5.2. Người dùng chỉ xem dữ liệu theo scope/domain nhất định

```text
users@osdu.group
users.datalake.viewers@osdu.group

data.<scope>.viewers@osdu.group

service.search.user@osdu.group
service.storage.viewer@osdu.group
service.legal.user@osdu.group
service.policy.user@osdu.group
```


Ví dụ chỉ xem WKE:

```text
users@osdu.group
users.datalake.viewers@osdu.group
data.wke.viewers@osdu.group
service.search.user@osdu.group
service.storage.viewer@osdu.group
service.legal.user@osdu.group
service.policy.user@osdu.group
```

Ví dụ chỉ xem IHS:

```text
users@osdu.group
users.datalake.viewers@osdu.group
data.ihs.viewers@osdu.group
service.search.user@osdu.group
service.storage.viewer@osdu.group
service.legal.user@osdu.group
service.policy.user@osdu.group
```

Lưu ý: nếu record đang dùng ACL `data.default.viewers@osdu.group`, user phải có `data.default.viewers@osdu.group`. Nếu muốn giới hạn theo domain, cần update ACL record sang data group domain tương ứng.

### 5.3. Người dùng ingest metadata record, không upload file

Dùng cho user hoặc service account tạo metadata record qua Storage Service.

```text
users@osdu.group
users.datalake.editors@osdu.group

data.<scope>.owners@osdu.group
data.<scope>.viewers@osdu.group

service.storage.creator@osdu.group
service.storage.viewer@osdu.group
service.search.user@osdu.group
service.legal.user@osdu.group
service.policy.user@osdu.group
service.schema-service.viewers@osdu.group
```


### 5.4. Người dùng ingest metadata kèm file/dataset

Dùng cho user hoặc ứng dụng upload file, tạo dataset metadata và tạo record liên quan.

```text
users@osdu.group
users.datalake.editors@osdu.group

data.<scope>.owners@osdu.group
data.<scope>.viewers@osdu.group

service.storage.creator@osdu.group
service.storage.viewer@osdu.group
service.file.editors@osdu.group
service.file.viewers@osdu.group
service.dataset.editors@osdu.group
service.dataset.viewers@osdu.group
service.legal.user@osdu.group
service.policy.user@osdu.group
service.schema-service.viewers@osdu.group
service.search.user@osdu.group
```


### 5.5. Service account/client chuyên ingest dữ liệu

Dùng cho client/service account như ingestion pipeline, Airflow DAG, record loader hoặc parser job.

```text
users@osdu.group
users.datalake.editors@osdu.group

data.<scope>.owners@osdu.group
data.<scope>.viewers@osdu.group

service.storage.creator@osdu.group
service.storage.viewer@osdu.group
service.file.editors@osdu.group
service.dataset.editors@osdu.group
service.legal.user@osdu.group
service.policy.user@osdu.group
service.schema-service.viewers@osdu.group
service.search.user@osdu.group
```


Bổ sung theo công cụ ingestion chuyên biệt:

```text
service.datalakerecordloader.admin@osdu.group
service.jsoningestor.admin@osdu.group
service.csvparser.admin@osdu.group
service.xlsingestor.admin@osdu.group
service.lasparser.admin@osdu.group
service.unzipingestion.admin@osdu.group
service.shapeingestor.admins@osdu.group
```

Khuyến nghị: không sử dụng một service account ingestion có quyền quá rộng cho mọi domain. Nên tách service account theo scope, ví dụ:

```text
datafier-wellbore
datafier-seismic
datafier-reservoir
datafier-document
```

### 5.6. Ingest theo domain

#### 5.6.1. Wellbore ingest

```text
users@osdu.group
users.datalake.editors@osdu.group

data.wellbore.owners@osdu.group
data.wellbore.viewers@osdu.group

service.storage.creator@osdu.group
service.storage.viewer@osdu.group
service.file.editors@osdu.group
service.dataset.editors@osdu.group
service.legal.user@osdu.group
service.policy.user@osdu.group
service.schema-service.viewers@osdu.group
service.search.user@osdu.group
```

Nếu dùng parser LAS/CSV:

```text
service.lasparser.admin@osdu.group
service.csvparser.admin@osdu.group
```

#### 5.6.2. Seismic ingest

```text
users@osdu.group
users.datalake.editors@osdu.group

data.seismic.owners@osdu.group
data.seismic.viewers@osdu.group

service.storage.creator@osdu.group
service.storage.viewer@osdu.group
service.file.editors@osdu.group
service.dataset.editors@osdu.group
service.legal.user@osdu.group
service.policy.user@osdu.group
service.schema-service.viewers@osdu.group
service.search.user@osdu.group
```

Nếu dùng Seistore:

```text
service.seistore.admin@osdu.group
```

#### 5.6.3. Reservoir ingest

```text
users@osdu.group
users.datalake.editors@osdu.group

data.reservoir.owners@osdu.group
data.reservoir.viewers@osdu.group

service.storage.creator@osdu.group
service.storage.viewer@osdu.group
service.file.editors@osdu.group
service.dataset.editors@osdu.group
service.reservoir-dms.owners@osdu.group
service.legal.user@osdu.group
service.policy.user@osdu.group
service.schema-service.viewers@osdu.group
service.search.user@osdu.group
```

### 5.7. Người dùng quản trị Access Governance/User Admin

Dùng cho tài khoản quản trị có quyền thêm/xóa user khỏi group, kiểm tra membership và vận hành phân quyền.

```text
users@osdu.group
users.datalake.admins@osdu.group

service.entitlements.user@osdu.group
service.entitlements.admin@osdu.group
```

Nếu webapp cần list user từ Keycloak, backend hoặc service account quản trị cũng cần quyền Keycloak Admin API tương ứng, ví dụ `view-users` hoặc `manage-users` trong realm. Đây là quyền ở IAM/Keycloak, không phải group Entitlements của OSDU.

Không cấp cho user admin nếu không cần thiết:

```text
users.data.root@osdu.group
users.datalake.delegation@osdu.group
users.datalake.impersonation@osdu.group
service.partition.admin@osdu.group
service.storage.admin@osdu.group
service.policy.admin@osdu.group
service.legal.admin@osdu.group
```

### 5.8. Legal Admin

Dùng cho tài khoản quản lý Legal Tag.

```text
users@osdu.group
users.datalake.admins@osdu.group

service.legal.user@osdu.group
service.legal.editor@osdu.group
service.legal.admin@osdu.group
```

### 5.9. Policy Admin

Dùng cho tài khoản quản lý Policy Service, OPA/Rego rule hoặc policy enforcement.

```text
users@osdu.group
users.datalake.admins@osdu.group

service.policy.user@osdu.group
service.policy.admin@osdu.group
```

### 5.10. Schema Admin/Editor

Viewer schema:

```text
users@osdu.group
service.schema-service.viewers@osdu.group
```

Editor schema:

```text
users@osdu.group
users.datalake.editors@osdu.group
service.schema-service.viewers@osdu.group
service.schema-service.editors@osdu.group
```

System admin schema:

```text
users@osdu.group
users.datalake.admins@osdu.group
service.schema-service.admin@osdu.group
service.schema-service.system-admin@osdu.group
```

### 5.11. Ops/Platform Admin

Dùng cho đội vận hành nền tảng. Không cấp cho người dùng nghiệp vụ.

```text
users@osdu.group
users.datalake.ops@osdu.group
users.datalake.admins@osdu.group

service.partition.admin@osdu.group
service.storage.admin@osdu.group
service.search.admin@osdu.group
service.legal.admin@osdu.group
service.policy.admin@osdu.group
service.entitlements.admin@osdu.group
service.workflow.admin@osdu.group
service.messaging.admin@osdu.group
service.logstore.admin@osdu.group
service.schema-service.admin@osdu.group
```

### 5.12. Root/Super Admin/Break-glass

Chỉ sử dụng cho bootstrap, khắc phục sự cố nghiêm trọng hoặc migration đặc biệt. Không dùng làm tài khoản thao tác thường ngày.

```text
users@osdu.group
users.data.root@osdu.group
users.datalake.admins@osdu.group

service.entitlements.admin@osdu.group
service.partition.admin@osdu.group
service.storage.admin@osdu.group
service.legal.admin@osdu.group
service.policy.admin@osdu.group
service.schema-service.system-admin@osdu.group
```

Yêu cầu vận hành:

- Bật audit log.
- Giới hạn số lượng tài khoản.
- Không dùng cho hoạt động ingestion định kỳ.
- Không dùng cho người dùng nghiệp vụ thông thường.
- Nên có quy trình cấp quyền tạm thời và thu hồi sau khi hoàn tất tác vụ.

---

## 6. Khuyến nghị thiết kế data group theo nghiệp vụ

Danh mục hiện tại có ít DATA group production:

```text
data.default.viewers@osdu.group
data.default.owners@osdu.group
data.wke.viewers@osdu.group
data.wke.owners@osdu.group
data.ihs.viewers@osdu.group
```

Không nên duy trì toàn bộ dữ liệu production bằng `data.default.*` trong dài hạn. Để phân quyền linh hoạt, nên tạo data group theo domain, block, project hoặc data room.

### 6.1. Theo domain

```text
data.wellbore.viewers@osdu.group
data.wellbore.owners@osdu.group

data.seismic.viewers@osdu.group
data.seismic.owners@osdu.group

data.reservoir.viewers@osdu.group
data.reservoir.owners@osdu.group

data.well-delivery.viewers@osdu.group
data.well-delivery.owners@osdu.group
```

### 6.2. Theo block/project

```text
data.block-15-1.viewers@osdu.group
data.block-15-1.owners@osdu.group

data.block-15-2.viewers@osdu.group
data.block-15-2.owners@osdu.group
```

### 6.3. Theo data room

```text
data.dataroom-round-a.viewers@osdu.group
data.dataroom-round-a.owners@osdu.group
```

### 6.4. Ví dụ ACL record

```json
{
  "acl": {
    "viewers": [
      "data.wellbore.viewers@osdu.group"
    ],
    "owners": [
      "data.wellbore.owners@osdu.group"
    ]
  }
}
```

---

## 7. Quy tắc cấp quyền tối thiểu

1. Người dùng chỉ xem dữ liệu không cần `data.*.owners`.
2. Người dùng ingest cần `data.*.owners` trên scope ingest.
3. Service account ingest không nên có `users.data.root`.
4. User admin quản trị group không nhất thiết có quyền xem toàn bộ dữ liệu.
5. Legal admin không nhất thiết có quyền Storage admin.
6. Policy admin không nhất thiết có quyền Entitlements admin.
7. Data group phải khớp với ACL record. User group nghiệp vụ không thay thế được data group trong ACL.
8. Khi thay đổi group membership, cần logout/login lại hoặc clear token/cache.
9. Không log full JWT, refresh token, client secret hoặc password.
10. Các group delegation/impersonation phải được kiểm soát chặt vì có thể làm thay đổi ngữ cảnh truy cập.

---

## 8. Phụ lục: group kiểm thử không dùng cho production

| Group | Loại | Mục đích | Khuyến nghị |
|---|---|---|---|
| `data.test46.owners@osdu.group` | DATA | Group test | Không dùng trong record production; có thể xóa hoặc giữ riêng cho môi trường test |

---

## 9. Checklist khi tạo user mới

### 9.1. User viewer thông thường

- Có `users@osdu.group`.
- Có `users.datalake.viewers@osdu.group`.
- Có service groups tối thiểu: Search, Storage Viewer, Legal User, Policy User.
- Có data group khớp ACL record cần xem.
- Không có owner/admin group nếu không cần.

### 9.2. User ingest

- Có `users@osdu.group`.
- Có `users.datalake.editors@osdu.group`.
- Có service groups cho Storage Creator, Storage Viewer, Legal, Policy, Schema Viewer.
- Có File/Dataset editor nếu upload file.
- Có data owner group đúng scope.
- Không dùng root/admin nếu chỉ ingest.

### 9.3. User admin phân quyền

- Có `users@osdu.group`.
- Có `users.datalake.admins@osdu.group`.
- Có `service.entitlements.user@osdu.group`.
- Có `service.entitlements.admin@osdu.group`.
- Có quyền Keycloak Admin API nếu chức năng cần list/create/update user ở IAM.
- Không cấp `users.data.root` nếu không có nhu cầu break-glass.

### 9.4. Service account ingestion

- Có group nền nếu hệ thống yêu cầu membership partition.
- Có service group đúng với API gọi.
- Có data owner group đúng với scope dữ liệu.
- Không dùng tài khoản admin/root làm pipeline ingestion định kỳ.
- Tách service account theo domain hoặc project để dễ audit.

---

## 10. Kết luận

Cơ chế phân quyền OSDU cần được thiết kế theo lớp: `USER group` để xác định vai trò và membership partition, `SERVICE group` để kiểm soát quyền gọi API, `DATA group` để kiểm soát record qua ACL, và `Legal/Policy` để kiểm tra điều kiện tuân thủ. Thiết kế đúng nên tránh cấp quyền theo client ID hoặc cấp quyền admin/root quá rộng. Các bộ quyền tiêu chuẩn cần được áp dụng theo nguyên tắc tối thiểu quyền và tách biệt rõ giữa viewer, editor/ingestor, user admin, legal admin, policy admin, platform admin và root/break-glass.
