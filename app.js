const express = require("express");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const pool = require("./Db");

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
    secret: "clave_secreta",
    resave: false,
    saveUninitialized: false
}));


app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    try {
        const [rows] = await pool.query(
            "SELECT * FROM admin WHERE username = ?",
            [username]
        );

        if (rows.length === 0) {
            return res.json({ success: false, message: "Usuario no encontrado" });
        }

        const admin = rows[0];
        const valid = await bcrypt.compare(password, admin.password);

        if (!valid) {
            return res.json({ success: false, message: "Contraseña incorrecta" });
        }

        req.session.admin = admin.id;
        res.json({ success: true });

    } catch (error) {
        console.log(error);
        res.status(500).json({ message: "Error servidor" });
    }
});

function verificarSesion(req, res, next) {
    if (!req.session.admin) {
        return res.status(403).json({ message: "No autorizado" });
    }
    next();
}

app.get("/cursos", async (req, res) => {
    try {
        const [rows] = await pool.query("SELECT * FROM cursos");
        res.json(rows);
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: "Error al obtener cursos" });
    }
});


app.post("/cursos", verificarSesion, async (req, res) => {
    const { titulo, descripcion, profesor } = req.body;

    try {
        await pool.query(
            "INSERT INTO cursos (titulo, descripcion, profesor) VALUES (?, ?, ?)",
            [titulo, descripcion, profesor]
        );
        res.json({ message: "Curso creado correctamente" });

    } catch (error) {
        console.log(error);
        res.status(500).json({ message: "Error al crear curso" });
    }
});


app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.json({ message: "Sesión cerrada" });
    });
});

app.listen(3000, () => {
    console.log("🚀 Servidor en http://localhost:3000");
});