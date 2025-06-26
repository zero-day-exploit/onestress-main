CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    is_admin TINYINT(1) DEFAULT 0,
    is_active TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE attack_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    host VARCHAR(255) NOT NULL,
    port INT NOT NULL,
    duration INT NOT NULL,
    method VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE counters (
    name VARCHAR(50) PRIMARY KEY,
    value INT NOT NULL DEFAULT 0
);

INSERT INTO users (username, password, is_admin) VALUES
('admin', '$2y$10$z7Z3z5Z7z9Z1z3Z5z7Z9Zuz3Z5z7Z9Z1z3Z5z7Z9Zuz3Z5z7Z9Z1z', 1),
('user1', '$2y$10$a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6', 0),
('user2', '$2y$10$b1c2d3e4f5g6h7i8j9k0l1m2n3o4p5q6r7s8t9u0v1w2x3y4z5a6', 0);

INSERT INTO counters (name, value) VALUES ('visits', 0);