import { pool } from "../database.js";
import express from "express";

const app = express();
app.use(express.json()); //memparsing JSON request body
app.use(
    cors({
        origin: ["http://localhost:5173"]
    })
);

app.post("/api/register", async (req, res) =>{
    const hash = await argon2.hash(req.body.password);
    await pool.query(
        "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING *",
        [req.body.username, req.body.email, hash]
    );
    res.send("Registrasi berhasil");
} );

function authenticateToken(req, res, next){
    const authorization = req.headers.authorization;
    if(authorization && authorization.startsWith("Bearer ")){
        const token = authorization.split(" ")[1];
        try{
            req.user = jwt.verify(token, process.env.SECRET_KEY);
            next();
        }catch (error){
            res.status(401).send("Token tidak valid");
        }
    }else{
        res.status(401).send("Anda belum login");
    }
}

app.post("/api/login", async (req, res)=>{
    const result = await pool.query("SELECT * FROM users WHERE username = $1",
        [req.body.username]
    );
    if(res.rows.length > 0){
        const user = req.rows[0];
        if(await argon2.verify(user.password, req.body.password)){
            const token = jwt.sign(user, process.env.SECRET_KEY);
            res.json({
                token,
                message : "Login berhasil",
            })
        }else{
            res.status(401).send("Kata sandi salah");
        }
    }else{
        res.status(404).send(`Pengguna dengan nama ${req.body.username} tidak ditemukan`);
    }
});

//---------------------------------MANIPULASI CLASS---------------------------------
app.post("/api/add-class", async (req, res) =>{
    const result = await pool.query(
        "INSERT INTO class (name, kode) VALUES ($1, $2) RETURNING *",
        [req.body.name, req.body.kode]
    );
    res.json(result.rows[0]);
});


app.get("/api/class", async (req, res) => {
    const result = await pool.query("SELECT * FROM class");
    res.json(result.rows);
});

app.put("/api/update-class/:id", async (req, res) => {
    await pool.query(
        "UPDATE class SET name = $1, kode = $2 WHERE id = $3",
        [req.body.name, req.body.kode, req.params.id]
    );
    res.send("Class berhasil di update");
});

app.delete("/api/detele-class/:id", async (req, res) => {
    await pool.query("DELETE FROM class WHERE id = $1", [req.params.id]);
    res.send("Class berhasil di detele");
});

//---------------------------------MANIPULASI TASK---------------------------------
app.post("/api/add-task", async (req, res) =>{
    const result = await pool.query(
        "INSERT INTO task (title, deskripsi, deadline) VALUES ($1, $2, $3) RETURNING *",
        [req.body.title, req.body.deskripsi, req.body.deadline]
    );
    res.json(result.rows[0]);
});

app.get("/api/task", async (req, res) => {
    const result = await pool.query("SELECT * FROM task");
    res.json(result.rows);
});

app.put("/api/update-task/:id", async (req, res) => {
    await pool.query(
        "UPDATE task SET title = $1, deskripsi = $2, deadline = $3 WHERE id = $4",
        [req.body.title, req.body.deskripsi, req.body.deadline, req.params.id]
    );
    res.send("task berhasil di update");
});

app.delete("/api/detele-task/:id", async (req, res) => {
    await pool.query("DELETE FROM task WHERE id = $1", [req.params.id]);
    res.send("task berhasil di detele");
});


//---------------------------------MANIPULASI STUDENT---------------------------------
app.post("/api/add-student", async (req, res) =>{
    const result = await pool.query(
        "INSERT INTO enrollment (title, deskripsi, deadline) VALUES ($1, $2, $3) RETURNING *",
        [req.body.title, req.body.deskripsi, req.body.deadline]
    );
    res.json(result.rows[0]);
});

app.get("/api/student", async (req, res) => {
    const result = await pool.query("SELECT * FROM enrollment");
    res.json(result.rows);
});

// app.put("/api/update-task/:id", async (req, res) => {
//     await pool.query(
//         "UPDATE task SET title = $1, deskripsi = $2, deadline = $3 WHERE id = $4",
//         [req.body.title, req.body.deskripsi, req.body.deadline, req.params.id]
//     );
//     res.send("task berhasil di update");
// });

app.delete("/api/detele-student/:id", async (req, res) => {
    await pool.query("DELETE FROM enrollment WHERE id = $1", [req.params.id]);
    res.send("task berhasil di detele");
});













app.listen(3000, () => console.log("Server berhasil dijalankan"));

