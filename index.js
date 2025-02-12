import express from 'express'
import bodyParser from 'body-parser'
import pg from 'pg'
import bcrypt from 'bcrypt'
import passport from 'passport'
import { Strategy } from 'passport-local'
import GoogleStrategy from 'passport-google-oauth2'
import session from 'express-session'
import env from 'dotenv'
import multer from 'multer'

const app = express()
const upload = multer({ storage: multer.memoryStorage() })
const saltRounds = 10
env.config()

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT
})
db.connect()

app.use(bodyParser.urlencoded({ extended: true }))
app.use(express.static('public'))
app.set('view engine', 'ejs')
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 24 }
  })
)
app.use(passport.initialize())
app.use(passport.session())
env.config()
app.get('/', async function (req, res) {
  const result = await db.query('SELECT * FROM blogs')
  const Message = req.session.successMessage || null;
  req.session.successMessage = null;
  // console.log(Message)
  if (req.isAuthenticated()) {
    res.render('pages/index', {
      auth: true,
      user: req.user.username,
      blogs: result.rows,
      msg:Message
    })
  } else {
    res.render('pages/index',{ auth: false, user: null, blogs: result.rows, msg:Message })
  }
})
app.get('/signup', function (req, res) {
  res.render('pages/signup')
})
app.get('/login', function (req, res) {
  res.render('pages/login')
})

app.get("/search", async (req, res)=>{
  const auth = req.isAuthenticated()
  const search = req.query.query;
  const result = await db.query(
    "SELECT * FROM blogs WHERE author ILIKE $1",
    [search])
  if(result){
    res.render('pages/index', { auth: auth, user: req.user?.username || null, blogs: result.rows, msg:null })
  }else{
    res.render('pages/index', { auth: auth, user: req.user?.username || null, blogs: [], msg:null })
  }
})

//Signing Up
app.post('/createAccount', async function (req, res) {
  const user = req.body.username
  const name = req.body.fullname
  const pass = req.body.password
  const cpass = req.body.confirmpassword
  try {
    const checkUsernname = await db.query(
      'SELECT * FROM users where username = $1',
      [user]
    ) // to check that user already exists or username not available

    if (checkUsernname.rows.length > 0) {
      res.send('Username already exists...')
    } else {
      if (pass == cpass) {
        const hashedPass = bcrypt.hash(pass, saltRounds, async (err, hash) => {
          if (err) {
            console.log(err)
          } else {
            const result = await db.query(
              'INSERT INTO users(fullname,username,password) VALUES ($1,$2,$3) RETURNING *',
              [name, user, hash]
            )
            const user = result.rows[0]
            req.login(user, err => {
              if (err) {
                console.log(err)
              } else {
                res.redirect('/')
              }
            })
          }
        })
      } else {
        res.send('Password do not match')
      }
    }
  } catch (error) {
    console.log(error)
  }
})

//Logging In
app.post(
  '/loginUser',
  passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true // Show error messages if login fails
  })
)

//to display image
app.get('/image/:id', async (req, res) => {
  const { id } = req.params
  try {
    const result = await db.query(
      'SELECT image FROM blogs WHERE blog_id = $1',
      [id]
    )

    if (result.rows.length > 0) {
      const imageBuffer = result.rows[0].image
      // console.log(imageBuffer)
      res.setHeader('Content-Type', 'image/')
      res.send(imageBuffer)
    } else {
      res.status(404).send('Image not found')
    }
  } catch (err) {
    console.error('Error fetching image:', err)
    res.status(500).send('Error fetching image')
  }
})

//Create Blog
app.get('/create', (req, res) => {
  if (req.isAuthenticated()) {
    res.render('pages/create')
  } else {
    res.redirect('/login')
  }
})

//View my blogs only
app.get('/myblogs', async (req, res) => {
  if (req.isAuthenticated()) {
    const loggedUser = { id: req.user.id, username: req.user.username }
    // console.log(loggedUser)
    const blogs = await db.query('SELECT * FROM blogs WHERE user_id = $1', [
      loggedUser.id
    ])
    // console.log(blogs.rows[0])
    res.render('pages/myblogs', {
      username: loggedUser.username,
      blogs: blogs.rows
    })
  } else {
    res.redirect('/login')
  }
})

app.get('/logout', (req, res, next) => {
  req.logout(err => {
    if (err) return next(err)
    res.redirect('/')
  })
})

app.get(
  '/auth/google',
  passport.authenticate('google', {
    scope: ['profile', 'email']
  })
)

app.get(
  '/auth/google/index',
  passport.authenticate('google', {
    successRedirect: '/',
    failureRedirect: '/login'
  })
)

app.post('/submitBlog', upload.single('blog-img'), async (req, res) => {
  const title = req.body.title
  const author = req.body.author || req.user.username
  const image = req.file.buffer
  const content = req.body.content
  req.session.successMessage = "Your blog is submmited successfuly";
  try {
    const result = await db.query(
      'INSERT INTO blogs (title,author,image,content,user_id) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [title, author, image, content, req.user.id]
    )
    res.redirect("/");
  } catch (error) {
    console.log(error)
  }
})

app.get('/blog/:id', async (req, res) => {
  try {
    const id = req.params.id
    const blog = await db.query('SELECT * FROM blogs where blog_id = $1', [id])
    res.render('pages/blog', { blog: blog.rows[0] })
  } catch (error) {
    console.log(error)
  }
})

app.post('/delete',async (req,res)=>{
  try {
    const blog = await db.query('DELETE FROM blogs where blog_id = $1', [req.body.id])
    res.redirect("/myblogs")
  } catch (error) {
    console.log(error)
  }
})

passport.use(
  new Strategy(async function verify (username, password, cb) {
    try {
      const checkUsernname = await db.query(
        'SELECT * FROM users where username = $1',
        [username]
      ) // to check that user already exists or not
      if (checkUsernname.rows.length > 0) {
        bcrypt.compare(
          password,
          checkUsernname.rows[0].password,
          (err, valid) => {
            // console.log(checkUsernname.rows[0].password)
            if (err) {
              //Error with password check
              console.error('Error comparing passwords:', err)
              return cb(err)
            } else {
              if (valid) {
                //Passed password check
                return cb(null, checkUsernname.rows[0])
              } else {
                //Did not pass password check
                return cb(null, false)
              }
            }
          }
        )
      } else {
        res.send('Username not exists...')
      }
    } catch (error) {
      console.log(error)
    }
  })
)

passport.use(
  'google',
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: 'https://blogbogs.onrender.com/auth/google/index'
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        // console.log(profile);
        const result = await db.query('SELECT * FROM users WHERE email = $1', [
          profile.email
        ])
        if (result.rows.length === 0) {
          const newUser = await db.query(
            'INSERT INTO users (email, password, username) VALUES ($1, $2, $3) RETURNING *',
            [profile.email, 'google', profile.displayName.replace(/\s/g, '')]
          )
          return cb(null, newUser.rows[0])
        } else {
          return cb(null, result.rows[0])
        }
      } catch (err) {
        return cb(err)
      }
    }
  )
)

passport.serializeUser((user, cb) => {
  cb(null, user)
})
passport.deserializeUser((user, cb) => {
  cb(null, user)
})

const port = process.env.port || 3000

app.listen(port)
