// ===========================
//  Db.js - Conexión a MySQL
// ===========================

const mysql = require('mysql2/promise'); // Usamos mysql2 con soporte para Promesas
const pool = mysql.createPool({
  host:               'localhost', // Servidor donde está MySQL
  user:               'root',      // Tu usuario de MySQL
  password:           '',          // Tu contraseña de MySQL
  database:           'escuela',     // Nombre de tu base de datos
  waitForConnections: true,        // Espera si todas las conexiones están ocupadas
  connectionLimit:    10,          // Máximo de conexiones simultáneas
  queueLimit:         0            // Sin límite de solicitudes en espera (0 = ilimitado)
});

// -------------------------------------------------
// VERIFICAR QUE EL POOL FUNCIONA AL ARRANCAR
// -------------------------------------------------
(async () => {
  try {
    const connection = await pool.getConnection();
    console.log('✅ Pool MySQL listo');
    connection.release(); // Muy importante: regresamos la conexión al pool
  } catch (error) {
    console.error('❌ Error MySQL:', error.message);
  }
})();

// Exportamos el pool para usarlo en otros archivos
module.exports = pool;