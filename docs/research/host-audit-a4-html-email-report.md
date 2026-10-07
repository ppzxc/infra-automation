# Host Audit: A4 인쇄용 HTML 보고서의 이메일 발송 표준

[#104](https://github.com/ppzxc/infra-automation/issues/104) 리서치 결과입니다. 상위 맵은 [#100](https://github.com/ppzxc/infra-automation/issues/100)(Host Audit)입니다. 조사일은 2026-10-07입니다.
기준 자료: MDN browser-compat-data 8.1.4(2026-10-01), Can I Email API(2026-09-16 갱신), community.general `main`의 `plugins/modules/mail.py`(로컬 설치본 13.4.0).

## TL;DR

- **권장안은 "본문 요약 + 자체 완결형 `.html` 첨부 1개"입니다.**
  - 메일 본문에는 짧은 요약만 넣습니다. 실행 시각, 대상 수, 심각도별 건수, 상위 N개 항목 정도입니다. 스타일은 `style=""` 인라인과 `<table>`만 쓰고, 이미지와 SVG는 넣지 않습니다.
  - A4 인쇄 원본은 첨부한 `.html` 파일입니다. `<style>`, `@page`, 인라인 SVG 차트를 모두 파일 하나에 담고 외부 리소스는 쓰지 않습니다. 받는 사람은 이 파일을 브라우저로 열어 인쇄합니다.
- **본문만으로 인쇄 원본을 보내는 방식은 쓸 수 없습니다.**
  - Gmail은 `<style>`을 `<head>` 안에서만, 16KB까지만 허용합니다.
  - classic Outlook(Windows, Word 엔진)은 `@media`를 지원하지 않습니다.
  - Gmail과 Outlook 모두 인라인 `<svg>`와 base64 data URI 이미지를 지원하지 않습니다.
  - 따라서 `@page`나 인쇄 CSS를 메일 본문에 넣으면 메일 클라이언트에서 무시된다고 보아야 합니다.
- **PDF는 기본 경로가 아니라 조건부 옵션입니다.**
  - PDF가 필요해지는 경우는 두 가지입니다. 수신 측 메일 시스템이 `.html` 첨부를 차단하거나, 모든 뷰어에서 쪽번호가 반드시 찍혀야 하는 경우입니다.
  - 그 경우 비용이 듭니다. Semaphore 러너 이미지를 커스텀해야 하고(현재는 공식 `semaphoreui/semaphore:v2.19.12`, Alpine 3.21), CJK 폰트와 Chromium 또는 WeasyPrint를 넣어야 하며, 컨테이너 메모리 한도(현재 1024M)도 검토해야 합니다.
- **쪽번호가 이 결정의 분기점입니다.**
  - `@page` 여백 박스(`@bottom-center { content: counter(page) }`)는 **Chrome/Edge 131 이상에서만** 동작합니다. Firefox와 Safari는 BCD 기준 미지원입니다.
  - 따라서 `.html` 첨부로는 "Chrome/Edge로 인쇄하면 쪽번호가 나온다"까지만 약속할 수 있습니다.
- **`community.general.mail`만으로 구현할 수 있습니다.**
  - `subtype: html`, `charset: utf-8`(기본값), `attach`, `secure: starttls`를 지원합니다.
  - CID 인라인 이미지(`inline`)는 **13.3.0 이상**에서만 쓸 수 있는데, `requirements.yml`은 `>=8.0.0`입니다. 다만 권장안은 본문에 이미지를 쓰지 않으므로 버전을 올릴 필요가 없습니다.

## 1. 인쇄 CSS(첨부 `.html`용)

### 1.1 브라우저 지원(MDN BCD 8.1.4)

| 기능 | Chrome | Edge | Firefox | Safari | 비고 |
|---|---|---|---|---|---|
| `@page` | 2 | 12 | 19 | 18.2 | MDN: Baseline 2024 |
| `@page { size }` | 15 | 79 | 95 | 18.2 | `size: A4` 사용 가능. `landscape`/`portrait` 키워드는 Safari 미지원 |
| 여백 박스 `@top-*`/`@bottom-*` 등 16종 | **131** | **131** | ✗ | ✗ | 머리글, 바닥글, 쪽번호의 유일한 표준 수단 |
| `break-before/after: page` | 50 | 79 | 65 | 10 | |
| `break-inside: avoid` | 50 | 79 | 65 | 10 | |
| `break-before/after: avoid` | 50 | 79 | ✗(무시) | ✗(무시) | Firefox [bug 1972340](https://bugzil.la/1972340), WebKit [b/294559](https://webkit.org/b/294559) |
| `page-break-inside: avoid`(레거시) | 1 | 12 | 19 | 1.3 | 호환용으로 함께 선언 |
| `print-color-adjust: exact` | 136 | 136 | 97 | 15.4 | 136 미만 Chrome에서는 `-webkit-print-color-adjust`가 필요 |

출처: [MDN @page](https://developer.mozilla.org/en-US/docs/Web/CSS/@page). 표의 버전 수치는 `@mdn/browser-compat-data` `data.json`(v8.1.4)의 `css.at-rules.page.*`, `css.properties.break-*`, `print-color-adjust`에서 직접 추출했습니다. [caniuse: CSS Paged Media](https://caniuse.com/css-paged-media)도 함께 참고했습니다.

### 1.2 표 머리글 반복

- CSS 2.1 §17.2에 따르면 `thead`의 기본값은 `display: table-header-group`이고, 여러 쪽에 걸친 표에서 UA가 머리글 행을 반복할 수 있습니다(MAY). 반복이 의무는 아닙니다. ([CSS 2.1 §17.2](https://www.w3.org/TR/CSS21/tables.html#table-display))
- Chromium은 2016년에 반복 기능을 넣었습니다. [커밋 81c0fc6](https://chromium.googlesource.com/chromium/src/+/81c0fc6d4e08e4e2bb4eb8a42747f21b13303616)의 메시지는 다음과 같습니다.
  > "FF, IE and Edge all repeat a table header group at the top of each printed page. … we agreed to repeat the header group if it has break-inside:avoid. We make this the default style for theads when printing."
  - 따라서 Chrome, Edge, Firefox에서는 `<thead>`만 올바르게 쓰면 머리글이 반복됩니다. `thead { display: table-header-group; break-inside: avoid; }`를 명시해 두면 안전합니다.
- Safari의 반복 여부는 이번에 1차 출처로 확인하지 못했습니다(**미검증**).

### 1.3 한글 폰트(폐쇄망)

- 외부 웹폰트는 쓰지 않고 시스템 폰트 스택만 씁니다. 메일 클라이언트는 원격 `@font-face`를 대부분 무시합니다. Can I Email 기준으로 Gmail은 `n`, classic Outlook은 "distant fonts are ignored"입니다. 그래서 본문에서도 웹폰트가 이득이 없습니다.
- 권장 스택:
  `font-family: "Malgun Gothic", "맑은 고딕", "Apple SD Gothic Neo", "Noto Sans KR", "Noto Sans CJK KR", "NanumGothic", sans-serif;`
  - Windows는 맑은 고딕, macOS는 Apple SD Gothic Neo, Linux는 Noto CJK나 나눔 폰트를 씁니다.
- 숫자 표에는 `font-variant-numeric: tabular-nums`를 권장합니다.

### 1.4 권장 인쇄 CSS 골격

```css
@page { size: A4; margin: 15mm 12mm 18mm 12mm; }
@page { @bottom-center { content: counter(page) " / " counter(pages); font-size: 9pt; } } /* Chrome/Edge 131+ 전용 */
html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body { font-family: "Malgun Gothic","Apple SD Gothic Neo","Noto Sans CJK KR","NanumGothic",sans-serif; font-size: 10pt; }
thead { display: table-header-group; }
tr, .finding, figure { break-inside: avoid; page-break-inside: avoid; }
.host-appendix { break-before: page; page-break-before: always; }  /* 호스트별 부록마다 새 쪽 */
h2, h3 { break-after: avoid; } /* Chrome/Edge에서만 효과 */
@media screen { body { max-width: 210mm; margin: auto; } } /* 화면에서도 A4 폭으로 미리보기 */
```

- 쪽번호를 쓸 수 없는 브라우저를 위한 대비책도 둡니다. 표지와 각 부록 머리에 "보고서 ID / 호스트명 / 생성 시각"을 본문 텍스트로 넣어, 쪽번호 없이도 출력물을 식별할 수 있게 합니다.
- 브라우저 인쇄 대화상자의 "머리글과 바닥글" 옵션은 사용자 설정이라 CSS로 끌 수 없습니다. 여백 박스를 정의한 쪽의 해당 영역에서만 CSS가 UA 기본 머리글과 바닥글을 대체합니다.

### 1.5 차트와 이미지

| 방식 | 첨부 `.html`(브라우저) | 메일 본문 |
|---|---|---|
| 인라인 `<svg>` | 모든 브라우저에서 동작. 인쇄 시 벡터로 선명함 | Gmail, Outlook(전 플랫폼) **미지원** ([Can I Email html-svg](https://www.caniemail.com/features/html-svg/)) |
| `data:` URI(base64) | 동작 | Gmail(웹, iOS, Android) **미지원**. classic Outlook은 GIF 제외 부분 지원 ([image-base64](https://www.caniemail.com/features/image-base64/)) |
| `<img src="*.svg">` 외부/CID | 해당 없음 | Gmail은 PNG로 래스터화(2026-09 기준) ([image-svg](https://www.caniemail.com/features/image-svg/)) |
| CID(`cid:`) PNG | 해당 없음 | 메일 본문 이미지의 사실상 표준. `community.general.mail`의 `inline`(≥13.3.0) 필요 |
| 외부 URL 이미지 | 폐쇄망이라 불가 | 대부분 기본 차단, 폐쇄망이라 불가 |

결론: 차트는 첨부 `.html` 안에 **인라인 SVG**로 넣습니다(Jinja로 생성 가능하고 JS가 필요 없음). 본문에는 차트 대신 숫자 표를 씁니다.

## 2. 메일 클라이언트 동작

### 2.1 Can I Email 데이터(최신 테스트 행)

| 기능 | Gmail 웹 | Gmail iOS/Android | Outlook Windows(classic, Word 엔진) | Outlook.com | Outlook Mac | Apple Mail |
|---|---|---|---|---|---|---|
| `<style>` ([html-style](https://www.caniemail.com/features/html-style/)) | 부분: `<body>` 안 미지원, **16KB 한도** | 부분: 비 Google 계정 미지원 | 부분: 사용 전에 선언해야 함 | 지원 | 지원 | 지원 |
| `@media` ([css-at-media](https://www.caniemail.com/features/css-at-media/)) | 부분: 높이 기반 미지원 | 부분 | **미지원** | 부분 | 부분 | 지원 |
| `<link>` 외부 CSS ([html-link](https://www.caniemail.com/features/html-link/)) | 미지원 | 미지원 | 지원 | 미지원 | 미지원 | 지원 |
| `@font-face` ([css-at-font-face](https://www.caniemail.com/features/css-at-font-face/)) | 미지원 | 미지원 | 원격 폰트 무시 | 미지원 | 미지원 | 지원 |
| 인라인 `<svg>` | 미지원 | 미지원 | 미지원 | 미지원 | 미지원 | 지원(macOS 조건부) |

- Can I Email에는 `@page`와 `break-*` 항목이 없습니다. 메일 클라이언트 안에서 인쇄하는 동작은 표준화되거나 측정된 영역이 아닙니다.
- classic Outlook(2007 이후 Windows)은 Word의 HTML 렌더러로 본문을 표시합니다. ([Microsoft: Word 2007 HTML and CSS Rendering Capabilities in Outlook 2007](https://learn.microsoft.com/en-us/previous-versions/office/developer/office-2007/aa338201(v=office.12))) 이번 조사에서 이 문서의 개별 속성표(`page-break-*` 등)는 확인하지 않았습니다.
- **네이버와 다음(카카오) 메일은 Can I Email 데이터셋에 없습니다.** 이 데이터셋의 클라이언트 목록에 naver, daum, kakaomail이 없습니다. 두 웹메일의 `<style>`·CSS 처리 방식은 1차 출처가 없으므로 **미검증**이며 추정하지 않습니다. 실제 수신 테스트로 확인해야 합니다.
- Gmail이 본문 HTML이 약 102KB를 넘으면 "[메시지 잘림]"으로 자른다는 수치는 Google이 공개한 값이 아닙니다. 발송 서비스 벤더 블로그([ActiveCampaign](https://help.activecampaign.com/hc/en-us/articles/115001060524) 등)에 근거한 **2차 출처**입니다. 본문을 짧은 요약으로 제한해야 하는 근거로만 씁니다.

### 2.2 전달 방식 비교

| 방식 | 장점 | 단점 | 판단 |
|---|---|---|---|
| A. 본문만(인라인 CSS) | 첨부 없음, 바로 보임 | `@page`, `<style>`, SVG를 쓸 수 없음. 수십 호스트 부록이면 Gmail 잘림 위험. A4 레이아웃을 보장할 수 없음 | ✗ |
| B. `.html` 첨부만 | 인쇄 CSS와 SVG가 모두 동작. 생성이 단순함(Jinja 1벌) | 메일을 열어도 내용이 바로 보이지 않음. 일부 조직이 html 첨부를 차단할 수 있음 | △ |
| **C. 본문 요약 + `.html` 첨부** | 받은편지함에서 바로 요약 확인, 인쇄는 첨부로 | 템플릿이 2벌(요약/전체). 데이터 모델은 1개 | **권장** |
| D. C + PDF 첨부 | 쪽번호와 레이아웃이 모든 뷰어에서 같음. html 차단 환경 대비 | 러너에 Chromium/WeasyPrint와 CJK 폰트 필요. 커스텀 이미지, 메모리 부담, 파이프라인 추가 | 조건부 |
| E. 본문 요약 + PDF만 | 받는 쪽 호환성이 가장 높음 | D와 비용이 같고, 검색과 복사가 편한 HTML 원본이 없음 | 조건부 |

### 2.3 `.html` 첨부의 차단 가능성

- Gmail 차단 확장자 목록에는 `.html`/`.htm`이 **없습니다**. ([Google: 차단되는 파일 형식](https://support.google.com/mail/answer/6590))
- Microsoft Defender for Office 365의 공통 첨부 필터는 기본 목록에 `htm`/`html`이 **없지만**, 관리자가 선택할 수 있는 추가 목록에는 `htm, html, mht, mhtml, xhtml`이 있습니다. 이 필터는 확장자가 아니라 true type matching으로 판정하며, 그 대상에 `html`이 포함됩니다. ([MS Learn: Anti-malware protection](https://learn.microsoft.com/en-us/defender-office-365/anti-malware-protection-about))
- 결론적으로 기본 설정에서는 차단되지 않습니다. 다만 HTML 스머글링 대응으로 차단하는 조직이 있으므로 **수신 측 정책을 확인해야 합니다**(아래 열린 질문).

## 3. 크기 한도

| 구간 | 한도 | 출처 |
|---|---|---|
| Gmail(개인) 첨부 | 25MB. 초과 시 Drive 링크로 자동 전환(웹 발송 시) | [Google 지원 6584](https://support.google.com/mail/answer/6584) |
| Exchange Online | 기본 송신 35MB, 수신 36MB. 관리자가 최대 150MB까지 조정 가능. 외부로 나가면 **base64 인코딩으로 약 33% 증가** | [MS Learn: Exchange Online limits](https://learn.microsoft.com/en-us/office365/servicedescriptions/exchange-online-service-description/exchange-online-limits) |
| 네이버 메일 | 일반 첨부 10MB, 초과분은 대용량 첨부(2GB, 30일) | **2차 출처**(블로그). help.naver.com은 수집 불가 |
| SMTP 릴레이 | 미확인(열린 질문). Postfix라면 `message_size_limit` 기본값 10240000 bytes | [postconf(5)](https://www.postfix.org/postconf.5.html#message_size_limit) |

추정: 호스트 수십 대 분량의 텍스트와 인라인 SVG로 만든 HTML은 보통 수백 KB에서 수 MB이며, base64로 인코딩하면 약 1.33배가 됩니다. 이 추정이 맞다면 10MB 한도에도 여유가 있습니다. 다만 PDF는 폰트 임베딩 때문에 HTML보다 커질 수 있습니다. 실제 크기는 구현 시 측정해야 합니다.

## 4. `community.general.mail` 지원 범위

출처: [공식 문서(13.4.0)](https://docs.ansible.com/ansible/latest/collections/community/general/mail_module.html), [`plugins/modules/mail.py`](https://github.com/ansible-collections/community.general/blob/main/plugins/modules/mail.py). Context7 `/ansible-collections/community.general`로 라이브러리를 식별했고, 아래 줄 번호는 `main` 브랜치 원본(495줄) 기준입니다.

| 항목 | 사실 | 근거(mail.py) |
|---|---|---|
| `subtype` | `plain`(기본) 또는 `html` | L129, L297 |
| `charset` | 기본 `utf-8`. 제목도 `Header(subject, charset)`로 인코딩 | L124, L296, L401 |
| `attach` | 경로 리스트. 항상 `application/octet-stream` + `Content-disposition: attachment` + base64로 첨부 | L87–93, L439–446 |
| `inline` | CID 이미지(`path`, `cid`, `mime_type`). **`version_added: 13.3.0`** | L94–116, L454–467 |
| MIME 구조 | `MIMEMultipart()` 기본값이라 `multipart/mixed`. 그 안에 `text/html` 1개, 첨부, inline 이미지가 나란히 들어감. **`multipart/alternative`(plain 대체본)와 `multipart/related`는 없음** | L398, L434–435 |
| `secure` | `always` / `never` / `starttls` / `try`(기본). `try`는 먼저 SMTPS(암묵적 TLS)로 연결을 시도하고, 실패하면 평문 연결 후 STARTTLS를 시도. `starttls`는 서버가 STARTTLS를 제공하지 않으면 실패 | L136–145, L333–381 |
| 인증 | `username`과 `password`가 모두 있을 때만 로그인. 암호화 없이 보내면 경고 | L383–396 |
| 기타 | `headers`, `cc`, `bcc`, `ehlohost`(3.8.0), `message_id_domain`(8.2.0). `body`가 비면 제목을 본문으로 씀 | L156, L162, L330 |

구현 시 주의할 점:

- **한글 첨부 파일명.** `add_header(..., filename=...)`에 한글을 넘기면 RFC 2231 형식인 `filename*=utf-8''%ED%98%B8...`로 인코딩됩니다(로컬 Python으로 확인). 클라이언트마다 이 형식의 해석이 달라 깨질 수 있으므로, 파일명은 `host-audit-2026-10.html`처럼 **ASCII로** 짓습니다.
- **CID 이미지 위치.** CID 이미지가 `multipart/related`가 아닌 `mixed`에 들어가기 때문에, 일부 클라이언트는 본문 이미지를 첨부 목록에도 표시할 수 있습니다(**미검증**). 권장안은 본문 이미지를 쓰지 않으므로 이 문제를 피합니다.
- **실행 위치.** 메일 발송 태스크는 러너에서 `delegate_to: localhost` + `run_once: true`로 실행합니다. `attach` 경로는 러너 로컬 파일이어야 합니다. 릴레이 자격증명은 OpenBao에서 조회합니다(#100 전제).
- **`secure` 값.** 내부 릴레이가 25/587 포트에서 STARTTLS를 제공한다면 `secure: starttls`로 강제하는 편이 명시적입니다. 기본값 `try`는 먼저 SMTPS 연결을 시도했다가 실패하면 넘어가는 방식이라, 의도와 다르게 평문 발송으로 조용히 떨어질 수 있습니다.

예시(권장안):

```yaml
- name: Send Host Audit report
  community.general.mail:
    host: "{{ host_audit_smtp_host }}"
    port: 587
    secure: starttls
    username: "{{ host_audit_smtp_user }}"       # OpenBao lookup
    password: "{{ host_audit_smtp_password }}"   # OpenBao lookup
    sender: "Host Audit <host-audit@example.internal>"
    to: "{{ host_audit_mail_to }}"
    subject: "[Host Audit] {{ audit_period }} 점검 보고서 (Critical {{ n_crit }} / High {{ n_high }})"
    subtype: html
    charset: utf-8
    body: "{{ lookup('ansible.builtin.template', 'mail_summary.html.j2') }}"
    attach:
      - "{{ host_audit_out_dir }}/host-audit-{{ audit_period }}.html"
  delegate_to: localhost
  run_once: true
```

## 5. PDF 옵션의 전제(선택 시)

- **엔진**
  - 헤드리스 Chromium: `--headless --print-to-pdf=<path> --no-pdf-header-footer`. 스위치는 [Chromium `headless_command_switches.cc`](https://chromium.googlesource.com/chromium/src/+/main/components/headless/command_handler/headless_command_switches.cc)에 정의되어 있습니다. Chrome 132부터 기존 헤드리스 모드는 별도 바이너리 `chrome-headless-shell`로 분리됐습니다. ([Chrome for Developers: Headless](https://developer.chrome.com/docs/chromium/headless))
    - 첨부 `.html`을 Chrome에서 인쇄한 결과와 같습니다. 여백 박스와 쪽번호, 표 머리글 반복이 모두 됩니다.
  - WeasyPrint(PyPI 최신 70.0): `@page`, 여백 박스, 쪽 기반 카운터(알려진 제한 [#93](https://github.com/Kozea/WeasyPrint/issues/93))를 지원하고, SVG를 벡터로 출력하며, Fontconfig 시스템 폰트를 씁니다. ([WeasyPrint API reference](https://doc.courtbouillon.org/weasyprint/stable/api_reference.html)) 문서에서 표 머리글 반복은 확인하지 못했습니다(**미검증**).
- **러너 제약(확인한 사실)**
  - `../overseer/compose.yml`의 Semaphore는 공식 `semaphoreui/semaphore:v2.19.12` 이미지(최종 스테이지 `alpine:3.21`)를 그대로 쓰고, `memory: 1024M` 한도가 걸려 있습니다.
  - 따라서 PDF를 만들려면 다음이 필요합니다.
    - ① 커스텀 이미지 또는 사이드카
    - ② 폐쇄망이므로 이미지 빌드 시점에 CJK 폰트(예: Noto CJK)를 넣어 두기. 폰트가 없으면 한글이 두부(□)로 렌더링됨
    - ③ Chromium 메모리 사용량 검토
  - 이 비용이 PDF를 기본 경로에서 제외한 이유입니다.

## 6. #108(결과 보존과 이력)에 주는 함의

- 보존 대상 산출물은 **자체 완결형 `.html` 1개**와 그 원본 데이터(JSON)입니다. HTML은 외부 의존성이 없어 RustFS 같은 저장소에 그대로 보관해도 나중에 다시 열 수 있습니다.
- 메일 본문 요약은 보존 대상이 아닙니다. 요약은 같은 JSON에서 다시 생성할 수 있습니다.
- PDF를 도입한다면 같은 HTML에서 파생되는 산출물로 다룹니다.

## 열린 질문(사용자 확인 필요)

1. 수신자 메일 시스템(사내 Exchange/M365, Gmail/Workspace, 네이버웍스 등)이 `.html`/`.htm` 첨부를 차단하거나 격리하는가? 그렇다면 D 또는 E(PDF)로 전환해야 합니다.
2. 사용할 SMTP 릴레이의 최대 메시지 크기(Postfix라면 `message_size_limit`)와 포트/TLS 방식(25/587 STARTTLS 또는 465 SMTPS)은 무엇인가?
3. 쪽번호가 "Chrome/Edge로 인쇄할 때만" 나와도 되는가? 감사 증적 제출 시 모든 출력물에 쪽번호가 필수라면 PDF로 가야 합니다.
4. 네이버/다음 메일 수신자가 실제로 있는가? 있다면 본문 요약 HTML의 렌더링을 실제 수신으로 확인해야 합니다(1차 데이터 없음).

## 출처

- MDN: [@page](https://developer.mozilla.org/en-US/docs/Web/CSS/@page). browser-compat-data v8.1.4 `data.json`(unpkg `@mdn/browser-compat-data`)
- caniuse: [CSS Paged Media](https://caniuse.com/css-paged-media)
- W3C: [CSS 2.1 §17.2 table display](https://www.w3.org/TR/CSS21/tables.html#table-display)
- Chromium: [commit 81c0fc6 "Display table header groups at the top of each page"](https://chromium.googlesource.com/chromium/src/+/81c0fc6d4e08e4e2bb4eb8a42747f21b13303616), [headless_command_switches.cc](https://chromium.googlesource.com/chromium/src/+/main/components/headless/command_handler/headless_command_switches.cc), [Chrome Headless](https://developer.chrome.com/docs/chromium/headless)
- Can I Email: [API data.json](https://www.caniemail.com/api/data.json)(2026-09-16), [html-style](https://www.caniemail.com/features/html-style/), [css-at-media](https://www.caniemail.com/features/css-at-media/), [html-link](https://www.caniemail.com/features/html-link/), [css-at-font-face](https://www.caniemail.com/features/css-at-font-face/), [html-svg](https://www.caniemail.com/features/html-svg/), [image-svg](https://www.caniemail.com/features/image-svg/), [image-base64](https://www.caniemail.com/features/image-base64/)
- Microsoft: [Word 2007 HTML/CSS rendering in Outlook 2007](https://learn.microsoft.com/en-us/previous-versions/office/developer/office-2007/aa338201(v=office.12)), [Exchange Online limits](https://learn.microsoft.com/en-us/office365/servicedescriptions/exchange-online-service-description/exchange-online-limits), [Defender anti-malware: common attachments filter](https://learn.microsoft.com/en-us/defender-office-365/anti-malware-protection-about)
- Google: [Gmail 첨부 크기](https://support.google.com/mail/answer/6584), [Gmail 차단 파일 형식](https://support.google.com/mail/answer/6590)
- Ansible: [community.general.mail 문서](https://docs.ansible.com/ansible/latest/collections/community/general/mail_module.html), [mail.py 소스](https://github.com/ansible-collections/community.general/blob/main/plugins/modules/mail.py)
- WeasyPrint: [API reference](https://doc.courtbouillon.org/weasyprint/stable/api_reference.html), [PyPI](https://pypi.org/project/weasyprint/)
- Postfix: [postconf(5) message_size_limit](https://www.postfix.org/postconf.5.html#message_size_limit)
- Semaphore: [Dockerfile v2.19.12](https://github.com/semaphoreui/semaphore/blob/v2.19.12/deployment/docker/server/Dockerfile)
- 2차 출처(참고만): Gmail 102KB 잘림 — [ActiveCampaign](https://help.activecampaign.com/hc/en-us/articles/115001060524). 네이버 10MB/2GB — 블로그 검색 결과
