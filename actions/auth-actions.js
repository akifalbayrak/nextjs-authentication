"use server";

import { createAuthSession, destroySession } from "@/lib/auth";
import { hashUserPassword, verifyPassword } from "@/lib/hash";
import { createUser, getUserByEmail } from "@/lib/user";

import { redirect } from "next/navigation";

export async function signUp(prevState, formData) {
    const email = formData.get("email");
    const password = formData.get("password");

    let errors = {};

    if (!email.includes("@")) {
        errors.email = "Invalid email address";
    }

    if (password.trim().length < 8) {
        errors.password = "Password must be at least 8 characters";
    }

    if (Object.keys(errors).length > 0) {
        return { errors };
    }

    const hashedPassword = hashUserPassword(password);
    try {
        const id = createUser(email, hashedPassword);
        await createAuthSession(id);
        redirect("/training");
    } catch (error) {
        if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
            errors.email = "Email already exists";
            return { errors };
        }
        throw error;
    }
}

export async function login(prevState, formData) {
    const email = formData.get("email");
    const password = formData.get("password");

    const existingUser = getUserByEmail(email);
    if (!existingUser) {
        return { errors: { email: "Email not found" } };
    }

    const isValidPassword = verifyPassword(existingUser.password, password);
    if (!isValidPassword) {
        return { errors: { password: "Invalid password" } };
    }

    await createAuthSession(existingUser.id);
    redirect("/training");
}

export async function auth(mode, prevState, formData) {
    if (mode === "login") return login(prevState, formData);
    else signUp(prevState, formData);
}

export async function logout() {
    await destroySession();
    redirect("/");
}
