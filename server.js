require("dotenv").config();
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();
const db = new Database("orders.sqlite");
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, role TEXT);
CREATE TABLE IF NOT EXISTS orders(
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, phone TEXT NOT NULL,
 vehicle TEXT NOT NULL, type TEXT NOT NULL, design TEXT NOT NULL, size TEXT,
 colour TEXT, notes TEXT, total INTEGER NOT NULL, advance INTEGER NOT NULL,
 method TEXT NOT NULL, transaction_ref TEXT, proof_file TEXT,
 status TEXT NOT NULL DEFAULT 'Pending Approval', created_at TEXT DEFAULT CURRENT_TIMESTAMP
);`);
const upsert = db.prepare("INSERT OR IGNORE INTO users(username,password_hash,role) VALUES(?,?,?)");
upsert.run(process.env.OWNER_USERNAME || "owner", bcrypt.hashSync(process.env.OWNER_PASSWORD || "ChangeThisOwnerPassword123!", 12), "owner");
upsert.run(process.env.EMPLOYEE_USERNAME || "staff", bcrypt.hashSync(process.env.EMPLOYEE_PASSWORD || "ChangeThisStaffPassword123!", 12), "employee");

app.use(express.urlencoded({extended:true}));
app.use(express.json());
app.use(session({
 secret: process.env.SESSION_SECRET || "development-only-change-this",
 resave:false, saveUninitialized:false,
 cookie:{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:8*60*60*1000}
}));
const uploadDir=path.join(__dirname,"uploads");
fs.mkdirSync(uploadDir,{recursive:true});
const upload=multer({dest:uploadDir,limits:{fileSize:5*1024*1024},fileFilter:(req,file,cb)=>{
 if(!/^image\\/(jpeg|png|webp)$/.test(file.mimetype)) return cb(new Error("Only JPG, PNG or WEBP images are accepted"));
 cb(null,true);
}});
app.use("/uploads",express.static(uploadDir));
app.use(express.static(path.join(__dirname,"public")));

function auth(role){
 return (req,res,next)=>{
  if(!req.session.user) return res.status(401).json({error:"Login required"});
  if(role && req.session.user.role!==role && req.session.user.role!=="owner") return res.status(403).json({error:"Not permitted"});
  next();
 };
}
app.get("/api/config",(req,res)=>res.json({
 easypaisa:{name:process.env.EASYPAISA_ACCOUNT_NAME||"Set account details in .env",number:process.env.EASYPAISA_NUMBER||"Not configured"},
 jazzcash:{name:process.env.JAZZCASH_ACCOUNT_NAME||"Set account details in .env",number:process.env.JAZZCASH_NUMBER||"Not configured"},
 shopWhatsapp:process.env.SHOP_WHATSAPP||""
}));
app.post("/api/orders",upload.single("proof"),(req,res)=>{
 const b=req.body;
 const total=Number(b.total), advance=Number(b.advance);
 if(!b.name||!b.phone||!b.design||!Number.isInteger(total)||!Number.isInteger(advance)||total<0||advance<0||advance>total)
  return res.status(400).json({error:"Please check required fields and payment amounts"});
 if(!["Easypaisa","JazzCash"].includes(b.method)) return res.status(400).json({error:"Invalid payment method"});
 const result=db.prepare(`INSERT INTO orders(name,phone,vehicle,type,design,size,colour,notes,total,advance,method,transaction_ref,proof_file)
 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(b.name,b.phone,b.vehicle,b.type,b.design,b.size||"",b.colour||"",b.notes||"",total,advance,b.method,b.transaction_ref||"",req.file?req.file.filename:"");
 res.json({ok:true,id:result.lastInsertRowid,status:"Pending Approval"});
});
app.post("/api/login",(req,res)=>{
 const user=db.prepare("SELECT * FROM users WHERE username=?").get(req.body.username||"");
 if(!user||!bcrypt.compareSync(req.body.password||"",user.password_hash)) return res.status(401).json({error:"Incorrect username or password"});
 req.session.user={username:user.username,role:user.role};
 res.json({ok:true,user:{username:user.username,role:user.role}});
});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",(req,res)=>res.json({user:req.session.user||null}));
app.get("/api/orders",auth(),(req,res)=>{
 const rows=db.prepare("SELECT * FROM orders ORDER BY id DESC").all();
 res.json(rows);
});
app.patch("/api/orders/:id/status",auth(),(req,res)=>{
 const {status}=req.body;
 const allowed=req.session.user.role==="owner"?["Approved","Rejected"]:["In Progress","Ready"];
 if(!allowed.includes(status)) return res.status(403).json({error:"This role cannot set that status"});
 const result=db.prepare("UPDATE orders SET status=? WHERE id=?").run(status,Number(req.params.id));
 if(!result.changes) return res.status(404).json({error:"Order not found"});
 res.json({ok:true});
});
app.get("/api/health",(req,res)=>res.json({ok:true}));
app.use((err,req,res,next)=>res.status(400).json({error:err.message||"Request failed"}));
const port=Number(process.env.PORT||3000);
app.listen(port,()=>console.log(`Sufi Jakhro Autos app running on port ${port}`));
