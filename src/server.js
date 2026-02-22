require('dotenv').config();
const path = require('path');
const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const csrf = require('csurf');
const bcrypt = require('bcryptjs');
const cron = require('node-cron');
const nodemailer = require('nodemailer');
const dayjs = require('dayjs');
const utc = require('dayjs/plugin/utc');
const timezone = require('dayjs/plugin/timezone');
const { Pool } = require('pg');

dayjs.extend(utc);
dayjs.extend(timezone);

const app = express();
const PORT = process.env.PORT || 3000;
const tz = process.env.TZ || 'Asia/Jerusalem';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:5432/coupons_app'
});

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: false,
  auth: process.env.SMTP_USER
    ? {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    : undefined
});

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(
  session({
    store: new pgSession({ pool, tableName: 'user_sessions' }),
    secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 24 * 7, httpOnly: true }
  })
);

app.use(csrf());
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  res.locals.currentUser = req.session.user;
  res.locals.error = req.session.error;
  res.locals.success = req.session.success;
  delete req.session.error;
  delete req.session.success;
  next();
});

const normalizeCoupon = (row) => ({
  ...row,
  purchase_date: row.purchase_date ? dayjs(row.purchase_date).tz(tz).format('YYYY-MM-DD') : '',
  expiration_date: dayjs(row.expiration_date).tz(tz).format('YYYY-MM-DD')
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS coupons (
      id SERIAL PRIMARY KEY,
      title VARCHAR(255) NOT NULL,
      brand VARCHAR(255) NOT NULL,
      category VARCHAR(255),
      value NUMERIC(10,2) NOT NULL CHECK (value >= 0),
      purchase_date DATE,
      expiration_date DATE NOT NULL,
      status VARCHAR(20) NOT NULL CHECK (status IN ('active', 'used', 'expired')) DEFAULT 'active',
      notes TEXT,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS coupon_reminders (
      id SERIAL PRIMARY KEY,
      coupon_id INT NOT NULL REFERENCES coupons(id) ON DELETE CASCADE,
      reminder_date DATE NOT NULL,
      created_at TIMESTAMP DEFAULT NOW(),
      UNIQUE (coupon_id, reminder_date)
    );
  `);
}

async function syncExpiredCoupons() {
  await pool.query(
    `UPDATE coupons
     SET status = 'expired', updated_at = NOW()
     WHERE status = 'active' AND expiration_date < CURRENT_DATE`
  );
}

async function sendExpirationReminders() {
  if (!process.env.REMINDER_EMAIL_TO) return;

  const result = await pool.query(
    `SELECT c.*
     FROM coupons c
     LEFT JOIN coupon_reminders r
       ON r.coupon_id = c.id
       AND r.reminder_date = CURRENT_DATE
     WHERE c.status = 'active'
       AND c.expiration_date = CURRENT_DATE + INTERVAL '7 days'
       AND r.id IS NULL`
  );

  for (const coupon of result.rows) {
    const expirationFormatted = dayjs(coupon.expiration_date).tz(tz).format('DD/MM/YYYY');
    const text = `תזכורת לקופון שעומד לפוג בעוד 7 ימים:\nכותרת: ${coupon.title}\nמותג: ${coupon.brand}\nערך: ₪${coupon.value}\nתאריך תפוגה: ${expirationFormatted}`;

    await transporter.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: process.env.REMINDER_EMAIL_TO,
      subject: `תזכורת תפוגה: ${coupon.title}`,
      text
    });

    await pool.query('INSERT INTO coupon_reminders (coupon_id, reminder_date) VALUES ($1, CURRENT_DATE) ON CONFLICT DO NOTHING', [coupon.id]);
  }
}

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

app.get('/', (req, res) => res.redirect('/dashboard'));

app.get('/register', (req, res) => res.render('register'));
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password || password.length < 8) {
    req.session.error = 'יש להזין אימייל וסיסמה באורך 8 תווים לפחות.';
    return res.redirect('/register');
  }

  try {
    const users = await pool.query('SELECT COUNT(*)::int AS count FROM users');
    if (users.rows[0].count > 0) {
      req.session.error = 'המערכת מיועדת למשתמש יחיד בלבד. המשתמש כבר נוצר.';
      return res.redirect('/login');
    }

    const hash = await bcrypt.hash(password, 12);
    await pool.query('INSERT INTO users (email, password_hash) VALUES ($1, $2)', [email, hash]);
    req.session.success = 'ההרשמה הושלמה, ניתן להתחבר.';
    return res.redirect('/login');
  } catch {
    req.session.error = 'אירעה שגיאה בהרשמה.';
    return res.redirect('/register');
  }
});

app.get('/login', (req, res) => res.render('login'));
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  const user = result.rows[0];
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    req.session.error = 'פרטי התחברות שגויים.';
    return res.redirect('/login');
  }
  req.session.user = { id: user.id, email: user.email };
  res.redirect('/dashboard');
});

app.post('/logout', requireAuth, (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/dashboard', requireAuth, async (req, res) => {
  await syncExpiredCoupons();
  const [totals, expiringSoon, byCategory, byStatus] = await Promise.all([
    pool.query(`SELECT
      COALESCE(SUM(CASE WHEN status='active' THEN value ELSE 0 END), 0) AS active_value,
      COALESCE(SUM(CASE WHEN status='used' THEN value ELSE 0 END), 0) AS used_value
      FROM coupons`),
    pool.query(`SELECT COUNT(*)::int AS count FROM coupons WHERE status='active' AND expiration_date BETWEEN CURRENT_DATE AND CURRENT_DATE + INTERVAL '7 days'`),
    pool.query(`SELECT COALESCE(NULLIF(category, ''), 'ללא קטגוריה') AS category, COALESCE(SUM(value),0)::float AS total
                FROM coupons GROUP BY COALESCE(NULLIF(category, ''), 'ללא קטגוריה') ORDER BY total DESC`),
    pool.query(`SELECT status, COUNT(*)::int AS count FROM coupons GROUP BY status`)
  ]);

  res.render('dashboard', {
    totals: totals.rows[0],
    expiringSoon: expiringSoon.rows[0].count,
    byCategory: byCategory.rows,
    byStatus: byStatus.rows
  });
});

app.get('/coupons', requireAuth, async (req, res) => {
  await syncExpiredCoupons();
  const { status, category, q } = req.query;
  const params = [];
  const where = [];

  if (status && ['active', 'used', 'expired'].includes(status)) {
    params.push(status);
    where.push(`status = $${params.length}`);
  }
  if (category) {
    params.push(category);
    where.push(`category = $${params.length}`);
  }
  if (q) {
    params.push(`%${q}%`);
    where.push(`(title ILIKE $${params.length} OR brand ILIKE $${params.length})`);
  }

  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const coupons = await pool.query(`SELECT * FROM coupons ${whereSql} ORDER BY expiration_date ASC`, params);
  const categories = await pool.query("SELECT DISTINCT category FROM coupons WHERE category IS NOT NULL AND category <> '' ORDER BY category ASC");

  res.render('coupons', { coupons: coupons.rows.map(normalizeCoupon), categories: categories.rows, filters: { status, category, q } });
});

app.get('/coupons/new', requireAuth, (req, res) => res.render('coupon_form', { coupon: {}, action: '/coupons/new', isEdit: false }));

app.post('/coupons/new', requireAuth, async (req, res) => {
  const { title, brand, category, value, purchase_date, expiration_date, notes } = req.body;
  if (!title || !brand || !value || Number.isNaN(Number(value)) || Number(value) < 0 || !expiration_date) {
    req.session.error = 'נא למלא את כל השדות החובה ולוודא שערך הקופון מספרי.';
    return res.redirect('/coupons/new');
  }

  await pool.query(
    `INSERT INTO coupons (title, brand, category, value, purchase_date, expiration_date, status, notes, updated_at)
     VALUES ($1,$2,$3,$4,$5,$6,'active',$7,NOW())`,
    [title, brand, category || null, value, purchase_date || null, expiration_date, notes || null]
  );
  req.session.success = 'הקופון נוסף בהצלחה.';
  res.redirect('/coupons');
});

app.get('/coupons/:id/edit', requireAuth, async (req, res) => {
  const coupon = await pool.query('SELECT * FROM coupons WHERE id=$1', [req.params.id]);
  if (!coupon.rows.length) return res.redirect('/coupons');
  res.render('coupon_form', { coupon: normalizeCoupon(coupon.rows[0]), action: `/coupons/${req.params.id}/edit`, isEdit: true });
});

app.post('/coupons/:id/edit', requireAuth, async (req, res) => {
  const { title, brand, category, value, purchase_date, expiration_date, notes, status } = req.body;
  if (!title || !brand || !value || Number.isNaN(Number(value)) || Number(value) < 0 || !expiration_date) {
    req.session.error = 'נא למלא את כל השדות החובה ולוודא שערך הקופון מספרי.';
    return res.redirect(`/coupons/${req.params.id}/edit`);
  }

  const current = await pool.query('SELECT * FROM coupons WHERE id=$1', [req.params.id]);
  if (!current.rows.length) return res.redirect('/coupons');

  let nextStatus = status || current.rows[0].status;
  const isExpiredByDate = dayjs(expiration_date).isBefore(dayjs().tz(tz).startOf('day'));
  if (isExpiredByDate) nextStatus = 'expired';
  if (current.rows[0].status === 'expired' && nextStatus === 'active') nextStatus = 'expired';

  await pool.query(
    `UPDATE coupons
     SET title=$1, brand=$2, category=$3, value=$4, purchase_date=$5, expiration_date=$6, status=$7, notes=$8, updated_at=NOW()
     WHERE id=$9`,
    [title, brand, category || null, value, purchase_date || null, expiration_date, nextStatus, notes || null, req.params.id]
  );

  req.session.success = 'הקופון עודכן בהצלחה.';
  res.redirect('/coupons');
});

app.post('/coupons/:id/use', requireAuth, async (req, res) => {
  await syncExpiredCoupons();
  await pool.query(`UPDATE coupons SET status='used', updated_at=NOW() WHERE id=$1 AND status <> 'expired'`, [req.params.id]);
  res.redirect('/coupons');
});

app.post('/coupons/:id/delete', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM coupons WHERE id=$1', [req.params.id]);
  req.session.success = 'הקופון נמחק.';
  res.redirect('/coupons');
});

cron.schedule('0 8 * * *', async () => {
  try {
    await syncExpiredCoupons();
    await sendExpirationReminders();
  } catch (error) {
    console.error('Reminder job failed:', error.message);
  }
}, { timezone: tz });

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Coupon app running on http://localhost:${PORT}`);
    });
  })
  .catch((error) => {
    console.error('DB init failed', error);
    process.exit(1);
  });
