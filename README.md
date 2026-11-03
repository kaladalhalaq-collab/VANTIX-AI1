# VANTIX AI – Backend

خادم Node.js (Express + SQLite) يوفّر: تسجيل الدخول، التحليل بالصور عبر Claude، المساعد الذكي، الاشتراكات بأكواد التفعيل، لوحة المستخدم، ولوحة الإدارة (API).

## التشغيل المحلي

```bash
cd vantix-backend
npm install
cp .env.example .env     # ثم املأ JWT_SECRET و ANTHROPIC_API_KEY و ADMIN_EMAIL و ADMIN_PASSWORD
npm start
```

اختبر: `curl http://localhost:3000/api/health` يجب أن يعيد `{"ok":true,"ai":true}`.

## ربط الواجهة (vantix.html)

في الواجهة أضف قبل وسم السكربت الرئيسي:

```html
<script>window.VANTIX_API = 'https://عنوان-الخادم-الخاص-بك';</script>
```

وضع عنوان الواجهة في `CORS_ORIGIN` داخل `.env`.

> الواجهة الكاملة (`vantix.html`) فيها شاشة دخول وتسجيل؛ يكفي إدخال رابط الخادم من زر الحساب، فلا حاجة لتعديل الكود.

## التحليل التلقائي

الخادم يجلب بيانات الشموع بنفسه (Binance للعملات الرقمية، وTwelve Data للذهب والفوركس والمؤشرات إن وُضع المفتاح) ثم يرسلها إلى Claude كل `AUTO_INTERVAL_MIN` دقيقة، ويحفظ الإشارات. تظهر في صفحة "تلقائي" بالواجهة. لا يُخصم من حصة المستخدم، وخطة Free ترى أول سوقين فقط. للتشغيل الفوري: زر "تشغيل التحليل التلقائي الآن" في لوحة الإدارة. رموز Twelve Data للمؤشرات (NDX وDJI) قد تتطلب خطة أعلى عندهم.

## النشر

للنشر على Render: ارفع مجلد backend إلى GitHub، ثم أنشئ Blueprint من `render.yaml` واملأ المتغيرات الناقصة. أو أي استضافة تدعم Node.js وقرصًا دائمًا لقاعدة SQLite (Render أو Railway أو VPS). اضبط المتغيرات من لوحة الاستضافة، وضع `DB_PATH` داخل القرص الدائم، و`TRUST_PROXY=1`. الاستضافة الثابتة وحدها لا تكفي.

## المسارات

| المسار | الوصف |
|---|---|
| `GET /api/health` | فحص الحالة |
| `POST /api/auth/register` · `/login` | `{email, password}` ← `{token, user}` |
| `GET /api/me` | المستخدم وحصص الاستخدام |
| `POST /api/analyze` | multipart: `image, market, timeframe, style, lang` |
| `POST /api/chat` · `GET/DELETE /api/chat/history` | المساعد وسجل المحادثة |
| `POST /api/subscription/activate` | `{code}` |
| `GET/POST /api/trades` · `PATCH /api/trades/:id/close` · `GET /api/stats` | الصفقات والإحصاءات |
| `GET/PUT/DELETE /api/watchlist/:market` | المفضلة |
| `GET /api/lessons` · `/news` · `/notifications` | المحتوى |

كل المسارات عدا الصحة والدخول والتسجيل تتطلب `Authorization: Bearer <token>`.

## مسارات الإدارة (`/api/admin/*`، للمدير فقط)

`GET/POST /users` · `PATCH/DELETE /users/:id` · `POST/GET /codes` · `GET /usage` · `GET/PUT /settings` · `POST/DELETE /news` · `POST/DELETE /lessons` · `POST /notifications`

أمثلة:

```bash
# دخول المدير
curl -X POST $API/api/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"..."}'

# توليد 5 أكواد PRO لمدة 30 يومًا
curl -X POST $API/api/admin/codes -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"plan":"pro","days":30,"count":5}'

# تغيير الحدود (analyses_* شهريًا، chat_* يوميًا) وأسعار تقدير التكلفة
curl -X PUT $API/api/admin/settings -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"analyses_free":5,"analyses_pro":150}'
```

## الأمان المطبّق

- كلمات المرور بـ bcrypt (12 جولة)، والجلسات JWT لمدة 7 أيام، ويُقرأ المستخدم من القاعدة في كل طلب، فالحذف وتغيير الصلاحيات يسريان فورًا.
- مفتاح Anthropic وJWT في متغيرات البيئة فقط ولا يصلان للواجهة.
- Rate Limiting عام، وأشد على الدخول والتسجيل، ولكل مستخدم على التحليل والمحادثة.
- التحقق من كل المدخلات بـ zod، والتحقق من نوع الصورة من محتواها (magic bytes) وليس من امتدادها.
- الحصص تُفرض في الخادم حسب الخطة وتاريخ انتهاء الاشتراك، وتعود الخطة تلقائيًا إلى FREE عند الانتهاء.
- لا تُعرض نتيجة تحليل إلا إذا أعاد النموذج JSON صالحًا، وإلا يعود خطأ واضح (502/422).
- سجل المحادثة يُقرأ من قاعدة البيانات لا من العميل، فلا يمكن حقن رسائل مزوّرة.

## الملف الشخصي والنقاط

`GET/PATCH /api/profile` · `PUT/GET/DELETE /api/profile/avatar` (JPG/PNG/WebP حتى 300KB) · `POST /api/auth/change-password` (يُبطل الجلسات القديمة) · `POST /api/auth/change-email` (يتطلب كلمة المرور، ويصبح البريد غير موثّق) · `DELETE /api/account` (يتطلب كلمة المرور). النقاط يمنحها المدير من لوحة الإدارة، وكل نقطة تمنح تحليلًا إضافيًا بعد نفاد الحصة الشهرية. الأعمدة الجديدة تُضاف تلقائيًا عند التشغيل دون فقد بيانات.

## غير مشمول بعد

توثيق البريد وإعادة تعيين كلمة المرور بالبريد (يتطلبان خدمة SMTP)، ودفع إلكتروني (الاشتراك حاليًا بأكواد يولدها المدير)، واختبارات آلية. التحليل أداة مساعدة وليس توصية مالية.
