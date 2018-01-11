package com.android.fastdeploy;

class PatchFormatException extends Exception {
    /**
     * Constructs a new exception with the specified message.
     * @param message the message
     */
    public PatchFormatException(String message) {
        super(message);
    }

    /**
     * Constructs a new exception with the specified message and cause.
     * @param message the message
     * @param cause the cause of the error
     */
    public PatchFormatException(String message, Throwable cause) {
        super(message);
        initCause(cause);
    }
}

