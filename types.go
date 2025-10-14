package main

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID        primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	FirstName string             `json:"firstName" bson:"firstName"`
	LastName  string             `json:"lastName" bson:"lastName"`
	Email     string             `json:"email"`
	Password  string             `json:"password" validate:"required,min=3,max=130"`
	CreatedAt time.Time          `json:"createdAt" bson:"createdAt"`
	Admin     bool               `json:"admin" bson:"admin"`
}

type Car struct {
	ID    primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Owner primitive.ObjectID `json:"owner" bson:"owner"`
	Placa string             `json:"placa" validate:"required"`
	Marca string             `json:"marca" validate:"required"`
	Color string             `json:"color" validate:"required"`
}

type RegisterUserPayload struct {
	FirstName string `json:"firstName" validate:"required"`
	LastName  string `json:"lastName" validate:"required"`
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=3,max=130"`
}

type LoginUserPayload struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type AccessToken struct {
	AccessToken string `json:"accessToken" bson:"accessToken"`
}

type NewCarPayload struct {
	Placa string `json:"placa" validate:"required"`
	Marca string `json:"marca" validate:"required"`
	Color string `json:"color" validate:"required"`
}

type NewCarEntryPayload struct {
	Placa string `json:"placa" validate:"required"`
}

type CarRegister struct {
	ID        primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Admin     User               `json:"admin" bson:"admin"`
	Car       Car                `json:"car" bson:"car"`
	EntryTime time.Time          `json:"entryTime" bson:"entryTime"`
	ExitTime  time.Time          `json:"exitTime,omitempty" bson:"exitTime,omitempty"`
	Paid      bool               `json:"paid" bson:"paid"`
	Amount    float64            `json:"amount,omitempty" bson:"amount,omitempty"`
}

type CarEntry struct {
	ID         primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	CarID      primitive.ObjectID `json:"carId" bson:"carId"`
	Owner      primitive.ObjectID `json:"owner" bson:"owner"`
	RegisterID primitive.ObjectID `json:"registerId" bson:"registerId"`
	Time       time.Time          `json:"Time" bson:"Time"`
	Type       string             `json:"type" bson:"type"`
}

type UserCarRegisters struct {
	Registers []CarRegister `json:"registers" bson:"registers"`
	Total     float64       `json:"total" bson:"total"`
}

type TotalBalance struct {
	Total float64 `json:"total" bson:"total"`
}
