"use server";

import { createAuthSession } from "@/lib/auth";
import { hashUserPassword } from "@/lib/hash";
import { createUser } from "@/lib/user";

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
