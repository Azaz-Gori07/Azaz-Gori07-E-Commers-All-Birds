import jwt from "jsonwebtoken";

// Token validate
export const authenticateToken = (req, res, next) => {
    const token = req.headers["authorization"]?.split(" ")[1];
    if (!token) return res.status(403).json({ error: "No token provided" });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(401).json({ error: "Invalid token" });

        req.user = user; // {id, email, role}
        next();
    });
};

// Role check
export const authorizeRoles = (...allowedRoles) => {
    return (req, res, next) => {
        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ error: "Access denied" });
        }
        next();
    };
};
