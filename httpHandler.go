package main

//Aquí creo los endpoints
//Crear una función que retorne en JSON los documentos de la colección containers que pertenezcan al usuario autenticado GET

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-playground/validator"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type handler struct {
	store *store
}

func NewHandler(store *store) *handler {
	return &handler{store: store}
}

func (h *handler) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /auth/signup", h.HandleUserRegister)
	mux.HandleFunc("POST /auth/login", h.HandleUserLogin)
	mux.HandleFunc("POST /new/car", WithJWTAuth(h.HandleNewCar, h.store.database))
	mux.HandleFunc("POST /new/car/entry", WithJWTAuth(h.HandleNewCarEntry, h.store.database))
	mux.HandleFunc("POST /new/car/exit", WithJWTAuth(h.HandleNewCarExit, h.store.database))

	mux.HandleFunc("POST /view/user", WithJWTAuth(h.HandleGetUser, h.store.database))

	mux.HandleFunc("GET /view/car/ActiveRegisters", WithJWTAuth(h.HandleActiveRegisters, h.store.database))
	mux.HandleFunc("GET /view/user/isAdmin", WithJWTAuth(h.HandleIsAdmin, h.store.database))
	mux.HandleFunc("GET /view/car/UserRegisters", WithJWTAuth(h.HandleUserRegisters, h.store.database))
}

func (h *handler) HandleUserRegister(w http.ResponseWriter, r *http.Request) {
	var payload RegisterUserPayload

	if err := ParseJSON(r, &payload); err != nil {
		log.Printf("Error parsing JSON: %v", err)
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := Validate.Struct(payload); err != nil {
		errors := err.(validator.ValidationErrors)
		formattedErrors := FormatValidationErrors(errors)
		WriteError(w, http.StatusBadRequest, "invalid payload: "+formattedErrors)
		return
	}

	_, err := h.store.GetUserByEmail(payload.Email)
	if err == nil {
		err = fmt.Errorf("user with email " + payload.Email + " already exists")
		WriteError(w, http.StatusConflict, err.Error())
		return
	}

	hashedPassword, err := HashPassword(payload.Password)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	_, err = h.store.CreateUser(User{
		FirstName: payload.FirstName,
		LastName:  payload.LastName,
		Email:     payload.Email,
		Password:  hashedPassword,
		CreatedAt: time.Now(),
		Admin:     false, // por defecto, no es admin
	})
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "failed to create user: "+err.Error())
		return
	}

	WriteJSON(w, http.StatusOK, "registered")

}

func (h *handler) HandleUserLogin(w http.ResponseWriter, r *http.Request) {
	var payload LoginUserPayload

	if err := ParseJSON(r, &payload); err != nil {
		log.Printf("Error parsing JSON: %v", err)
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := Validate.Struct(payload); err != nil {
		errors := err.(validator.ValidationErrors)
		formattedErrors := FormatValidationErrors(errors)
		WriteError(w, http.StatusBadRequest, "invalid payload: "+formattedErrors)
		return
	}

	user, err := h.store.GetUserByEmail(payload.Email)
	if err != nil {
		log.Printf("LoginUser: Failed to get user by email: %v, error: %v", payload.Email, err)
		WriteError(w, http.StatusUnauthorized, err.Error())
		return
	}

	//Se hashea la contraseña y se verifica si es la misma
	if !CheckPasswordHash(payload.Password, user.Password) {
		log.Printf("LoginUser: Invalid password for user with email: %s", payload.Email)
		WriteError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	// Successful login
	secret := []byte(JWTSecret)

	token, err := CreateJWT(secret, user.ID.Hex())
	if err != nil {
		log.Printf("LoginUser: Failed to create JWT for user with email %s: %v", payload.Email, err)
		WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	WriteJSON(w, http.StatusOK, token)

}

func (h *handler) HandleNewCar(w http.ResponseWriter, r *http.Request) {
	//Same
	userID, err := GetUserIDFromContext(r.Context())
	if err != nil {
		log.Printf("Unauthorized access: %v", err)
		WriteError(w, http.StatusUnauthorized, "unauthorized: "+err.Error())
		return
	}

	//

	var payload NewCarPayload //Tipo del JSON que se recibe en el ENDPOINT

	//Same
	if err := ParseJSON(r, &payload); err != nil { //Parsea el JSON al struct
		log.Printf("Error parsing JSON: %v", err)
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := Validate.Struct(payload); err != nil {
		errors := err.(validator.ValidationErrors)
		formattedErrors := FormatValidationErrors(errors)
		WriteError(w, http.StatusBadRequest, "invalid payload: "+formattedErrors)
		return
	}

	exists, err := h.store.CarExistsByPlaca(payload.Placa)
	if err != nil {
		log.Printf("Error checking if car exists: %v", err)
		WriteError(w, http.StatusInternalServerError, "failed to check car existence: "+err.Error())
		return
	}
	if exists {
		err = fmt.Errorf("carro con placa " + payload.Placa + " ya existe")
		WriteError(w, http.StatusConflict, err.Error())
		return
	}

	newCar := Car{
		Owner: userID, // Debe ser un primitive.ObjectID de un usuario existente
		Placa: payload.Placa,
		Marca: payload.Marca,
		Color: payload.Color,
	}

	_, err = h.store.CreateCar(newCar)
	if err != nil {
		log.Printf("Error creating car: %v", err)
		WriteError(w, http.StatusInternalServerError, "failed to register car: "+err.Error())
		return
	}

	WriteJSON(w, http.StatusOK, "New car registered successfully")
}

func (h *handler) HandleNewCarEntry(w http.ResponseWriter, r *http.Request) {
	userID, err := GetUserIDFromContext(r.Context())
	if err != nil {
		log.Printf("Unauthorized access: %v", err)
		WriteError(w, http.StatusUnauthorized, "unauthorized: "+err.Error())
		return
	}

	var payload NewCarEntryPayload

	if err := ParseJSON(r, &payload); err != nil {
		log.Printf("Error parsing JSON: %v", err)
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := Validate.Struct(payload); err != nil {
		errors := err.(validator.ValidationErrors)
		formattedErrors := FormatValidationErrors(errors)
		WriteError(w, http.StatusBadRequest, "invalid payload: "+formattedErrors)
		return
	}

	User, err := h.store.GetUserByObjectID(userID)
	if err != nil {
		log.Printf("Error getting user by ID: %v", err)
		WriteError(w, http.StatusNotFound, "user not found: "+err.Error())
		return
	}
	if !User.Admin {
		log.Printf("User %s is not admin", User.ID.Hex())
		WriteError(w, http.StatusForbidden, "permission denied: user is not admin")
		return
	}

	car, err := h.store.GetCarByPlaca(payload.Placa)
	if err != nil {
		log.Printf("Error getting car by placa: %v", err)
		WriteError(w, http.StatusNotFound, "car not found: "+err.Error())
		return
	}

	registerID, err := h.store.CreateCarRegister(CarRegister{
		Car:             *car,
		EntryTime:       time.Now(),
		Admin:           *User,
		ParkingLocation: payload.ParkingLocation,
	})
	if err != nil {
		log.Printf("Error creating car register: %v", err)
		WriteError(w, http.StatusInternalServerError, "error creando registro del carro: "+err.Error())
		return
	}

	_, err = h.store.CreateCarEntry(CarEntry{
		CarID:      car.ID,
		Owner:      car.Owner,
		RegisterID: registerID,
		Time:       time.Now(),
		Type:       "Entry",
	})
	if err != nil {
		log.Printf("Error creating car entry: %v", err)
		WriteError(w, http.StatusInternalServerError, "error creando registro del carro: "+err.Error())
		return
	}

	WriteJSON(w, http.StatusOK, "Carro con ID "+car.ID.Hex()+" registrado a las "+time.Now().Format(time.RFC1123))

}

func (h *handler) HandleNewCarExit(w http.ResponseWriter, r *http.Request) {
	var payload NewCarEntryPayload

	if err := ParseJSON(r, &payload); err != nil {
		log.Printf("Error parsing JSON: %v", err)
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := Validate.Struct(payload); err != nil {
		errors := err.(validator.ValidationErrors)
		formattedErrors := FormatValidationErrors(errors)
		WriteError(w, http.StatusBadRequest, "invalid payload: "+formattedErrors)
		return
	}

	car, err := h.store.GetCarByPlaca(payload.Placa)
	if err != nil {
		log.Printf("Error getting car by placa: %v", err)
		WriteError(w, http.StatusNotFound, "car not found: "+err.Error())
		return
	}

	registerID, err := h.store.GetActiveCarRegisterIDByPlaca(payload.Placa)
	if err != nil {
		log.Printf("Error getting active car register: %v", err)
		WriteError(w, http.StatusNotFound, "active car register not found: "+err.Error())
		return
	}

	_, err = h.store.CreateCarEntry(CarEntry{
		CarID:      car.ID,
		RegisterID: registerID,
		Owner:      car.Owner,
		Time:       time.Now(),
		Type:       "Exit",
	})
	if err != nil {
		log.Printf("Error creating car entry: %v", err)
		WriteError(w, http.StatusInternalServerError, "error creando registro del carro: "+err.Error())
		return
	}

	err = h.store.CloseCarRegister(registerID, 2)
	if err != nil {
		log.Printf("Error closing car register: %v", err)
		WriteError(w, http.StatusInternalServerError, "error cerrando registro del carro: "+err.Error())
		return
	}

	WriteJSON(w, http.StatusOK, "Carro con ID "+car.ID.Hex()+" registrado a las "+time.Now().Format(time.RFC1123))

}

func (h *handler) HandleGetUser(w http.ResponseWriter, r *http.Request) {

	var payload GetUserPayload

	if err := ParseJSON(r, &payload); err != nil {
		log.Printf("Error parsing JSON: %v", err)
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := Validate.Struct(payload); err != nil {
		errors := err.(validator.ValidationErrors)
		formattedErrors := FormatValidationErrors(errors)
		WriteError(w, http.StatusBadRequest, "invalid payload: "+formattedErrors)
		return
	}

	UserObjectID, err := primitive.ObjectIDFromHex(payload.UserID)
	if err != nil {
		log.Printf("Error converting UserID to ObjectID: %v", err)
		WriteError(w, http.StatusBadRequest, "invalid UserID: "+err.Error())
		return
	}

	FirstName, LastName, Email, err := h.store.GetUserBasicInfo(UserObjectID)
	if err != nil {
		log.Printf("Error getting active car registers: %v", err)
		WriteError(w, http.StatusInternalServerError, "error getting active car registers: "+err.Error())
		return
	}

	response := PublicUser{
		FirstName: FirstName,
		LastName:  LastName,
		Email:     Email,
	}

	WriteJSON(w, http.StatusOK, response)

}

func (h *handler) HandleIsAdmin(w http.ResponseWriter, r *http.Request) {
	userID, err := GetUserIDFromContext(r.Context())
	if err != nil {
		log.Printf("Unauthorized access: %v", err)
		WriteError(w, http.StatusUnauthorized, "unauthorized: "+err.Error())
		return
	}

	User, err := h.store.GetUserByObjectID(userID)
	if err != nil {
		log.Printf("Error getting user by ID: %v", err)
		WriteError(w, http.StatusNotFound, "user not found: "+err.Error())
		return
	}

	response := IsAdmin{
		Admin: User.Admin,
	}

	WriteJSON(w, http.StatusOK, response)

}

func (h *handler) HandleActiveRegisters(w http.ResponseWriter, r *http.Request) {
	userID, err := GetUserIDFromContext(r.Context())
	if err != nil {
		log.Printf("Unauthorized access: %v", err)
		WriteError(w, http.StatusUnauthorized, "unauthorized: "+err.Error())
		return
	}

	User, err := h.store.GetUserByObjectID(userID)
	if err != nil {
		log.Printf("Error getting user by ID: %v", err)
		WriteError(w, http.StatusNotFound, "user not found: "+err.Error())
		return
	}
	if !User.Admin {
		log.Printf("User %s is not admin", User.ID.Hex())
		WriteError(w, http.StatusForbidden, "permission denied: user is not admin")
		return
	}

	carsRegisters, err := h.store.GetActiveCarRegisters()
	if err != nil {
		log.Printf("Error getting active car registers: %v", err)
		WriteError(w, http.StatusInternalServerError, "error getting active car registers: "+err.Error())
		return
	}

	WriteJSON(w, http.StatusOK, carsRegisters)

}

func (h *handler) HandleUserRegisters(w http.ResponseWriter, r *http.Request) {
	userID, err := GetUserIDFromContext(r.Context())
	if err != nil {
		log.Printf("Unauthorized access: %v", err)
		WriteError(w, http.StatusUnauthorized, "unauthorized: "+err.Error())
		return
	}

	carsRegisters, total, err := h.store.GetCarRegistersByOwner(userID)
	if err != nil {
		log.Printf("Error getting active car registers: %v", err)
		WriteError(w, http.StatusInternalServerError, "error getting active car registers: "+err.Error())
		return
	}
	UserCarRegisters := UserCarRegisters{
		Registers: carsRegisters,
		Total:     total,
	}
	WriteJSON(w, http.StatusOK, UserCarRegisters)

}

func (h *handler) HandleUserCars(w http.ResponseWriter, r *http.Request) {
	userID, err := GetUserIDFromContext(r.Context())
	if err != nil {
		log.Printf("Unauthorized access: %v", err)
		WriteError(w, http.StatusUnauthorized, "unauthorized: "+err.Error())
		return
	}

	cars, err := h.store.GetCarsByOwner(userID)
	if err != nil {
		log.Printf("Error getting active car registers: %v", err)
		WriteError(w, http.StatusInternalServerError, "error getting active car registers: "+err.Error())
		return
	}

	WriteJSON(w, http.StatusOK, cars)

}

func (h *handler) HandleUserRegistersTotal(w http.ResponseWriter, r *http.Request) {
	userID, err := GetUserIDFromContext(r.Context())
	if err != nil {
		log.Printf("Unauthorized access: %v", err)
		WriteError(w, http.StatusUnauthorized, "unauthorized: "+err.Error())
		return
	}

	total, err := h.store.GetCarRegistersTotalBalanceByOwner(userID)
	if err != nil {
		log.Printf("Error getting active car registers: %v", err)
		WriteError(w, http.StatusInternalServerError, "error getting active car registers: "+err.Error())
		return
	}

	TotalBalance := TotalBalance{
		Total: total,
	}

	WriteJSON(w, http.StatusOK, TotalBalance)

}
