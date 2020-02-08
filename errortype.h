enum ErrorType {
	UNKNOWN_ERROR,
	INVALID_INPUT,
	INTEGRITY_VIOLATION,
	INVALID_FILE_PATH, // Used by init and load_file
	SUCCESS_NEW_FILE, // Used by init and load_file
	SUCCESS_FILE_EXISTS, // Used by init and load_file
	SUCCESS
};

