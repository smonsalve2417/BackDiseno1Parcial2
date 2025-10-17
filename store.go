package main

//Son todas las funciones que interactúan con la base de datos y Docker

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type store struct {
	mongoClient *mongo.Client
	database    *mongo.Database
}

func NewStore(mongoClient *mongo.Client) *store {
	return &store{mongoClient: mongoClient, database: mongoClient.Database(mongoDatabaseName)}
}

func (s *store) CreateUser(user User) (primitive.ObjectID, error) {
	collection := s.database.Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := collection.InsertOne(ctx, user)
	if err != nil {
		return primitive.NilObjectID, err // Return nil ObjectID on error
	}

	// Extract the inserted ID, assuming it's an ObjectID
	insertedID, ok := result.InsertedID.(primitive.ObjectID)
	if !ok {
		return primitive.NilObjectID, fmt.Errorf("inserted document ID is not an ObjectID")
	}

	return insertedID, nil
}

// GetUserByID implements UserStore.
func (s *store) GetUserByObjectID(id primitive.ObjectID) (*User, error) {
	collection := s.database.Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"_id": id}
	var user User

	err := collection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("user not found: id %s", id.Hex())
		}
		return nil, err
	}
	return &user, nil
}

func (s *store) GetUserByEmail(email string) (*User, error) {
	collection := s.database.Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"email": email}
	var user User

	err := collection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}

	return &user, err
}

func (s *store) CreateCar(car Car) (primitive.ObjectID, error) {
	collection := s.database.Collection("cars")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := collection.InsertOne(ctx, car)
	if err != nil {
		return primitive.NilObjectID, err
	}

	insertedID, ok := result.InsertedID.(primitive.ObjectID)
	if !ok {
		return primitive.NilObjectID, fmt.Errorf("inserted document ID is not an ObjectID")
	}

	return insertedID, nil
}

func (s *store) CarExistsByPlaca(placa string) (bool, error) {
	collection := s.database.Collection("cars")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"placa": placa}

	var result Car
	err := collection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func (s *store) GetCarIDByPlaca(placa string) (primitive.ObjectID, error) {
	collection := s.database.Collection("cars")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"placa": placa}

	var car struct {
		ID primitive.ObjectID `bson:"_id"`
	}

	err := collection.FindOne(ctx, filter).Decode(&car)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return primitive.NilObjectID, fmt.Errorf("carro con placa %s no encontrado", placa)
		}
		return primitive.NilObjectID, err
	}

	return car.ID, nil
}

func (s *store) GetCarByPlaca(placa string) (*Car, error) {
	collection := s.database.Collection("cars")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"placa": placa}

	var car Car
	err := collection.FindOne(ctx, filter).Decode(&car)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("carro con placa %s no encontrado", placa)
		}
		return nil, err
	}

	return &car, nil
}

func (s *store) CreateCarRegister(register CarRegister) (insertedID primitive.ObjectID, err error) {
	collection := s.database.Collection("car_registers")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Si no tiene hora de entrada, la ponemos ahora
	if register.EntryTime.IsZero() {
		register.EntryTime = time.Now()
	}

	// Asegurar que ExitTime quede vacío (no asignado)
	register.ExitTime = time.Time{}
	register.Paid = false // por defecto, no pagado
	register.Amount = 0.0

	result, err := collection.InsertOne(ctx, register)
	if err != nil {
		return primitive.NilObjectID, err
	}

	insertedID, ok := result.InsertedID.(primitive.ObjectID)
	if !ok {
		return primitive.NilObjectID, fmt.Errorf("inserted document ID is not an ObjectID")
	}

	return insertedID, nil
}

func (s *store) CreateCarEntry(entry CarEntry) (primitive.ObjectID, error) {
	collection := s.database.Collection("car_entries")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Si no se especifica la hora, la ponemos al momento actual
	if entry.Time.IsZero() {
		entry.Time = time.Now()
	}

	result, err := collection.InsertOne(ctx, entry)
	if err != nil {
		return primitive.NilObjectID, err
	}

	insertedID, ok := result.InsertedID.(primitive.ObjectID)
	if !ok {
		return primitive.NilObjectID, fmt.Errorf("inserted document ID is not an ObjectID")
	}

	return insertedID, nil
}

func (s *store) GetActiveCarRegisterIDByPlaca(placa string) (primitive.ObjectID, error) {
	collection := s.database.Collection("car_registers")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Filtro: carro con la placa indicada y sin ExitTime
	filter := bson.M{
		"car.placa": placa,
		"exitTime":  bson.M{"$eq": time.Time{}}, // exitTime vacío
	}

	// Solo queremos el campo _id y el más reciente
	opts := options.FindOne().
		SetProjection(bson.M{"_id": 1}).
		SetSort(bson.D{{Key: "entryTime", Value: -1}})

	var result struct {
		ID primitive.ObjectID `bson:"_id"`
	}

	err := collection.FindOne(ctx, filter, opts).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return primitive.NilObjectID, fmt.Errorf("no hay registro activo para la placa %s", placa)
		}
		return primitive.NilObjectID, err
	}

	return result.ID, nil
}

func (s *store) CloseCarRegister(registerID primitive.ObjectID, ratePerHour float64) error {
	collection := s.database.Collection("car_registers")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Buscar el registro por ID
	var register CarRegister
	err := collection.FindOne(ctx, bson.M{"_id": registerID}).Decode(&register)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return fmt.Errorf("no se encontró el registro con ID %s", registerID.Hex())
		}
		return err
	}

	// Calcular diferencia de tiempo (en horas, con decimales)
	exitTime := time.Now()
	duration := exitTime.Sub(register.EntryTime).Hours()

	// Calcular monto según tarifa por hora
	amount := duration * ratePerHour
	if amount < ratePerHour {
		amount = ratePerHour // cobrar mínimo una hora
	}

	// Actualizar el documento
	update := bson.M{
		"$set": bson.M{
			"exitTime": exitTime,
			"amount":   amount,
			"paid":     true,
		},
	}

	_, err = collection.UpdateByID(ctx, registerID, update)
	if err != nil {
		return fmt.Errorf("error actualizando registro: %v", err)
	}

	return nil
}

func (s *store) GetActiveCarRegisters() ([]CarRegister, error) {
	collection := s.database.Collection("car_registers")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Filtro: ExitTime aún no asignado
	filter := bson.M{
		"exitTime": time.Time{},
	}

	cursor, err := collection.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var registers []CarRegister
	if err := cursor.All(ctx, &registers); err != nil {
		return nil, err
	}

	return registers, nil
}

func (s *store) GetCarRegistersByOwner(userID primitive.ObjectID) ([]CarRegister, float64, error) {
	collection := s.database.Collection("car_registers")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Filtro por propietario del carro
	filter := bson.M{
		"car.owner": userID,
	}

	cursor, err := collection.Find(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("error buscando registros: %v", err)
	}
	defer cursor.Close(ctx)

	var registers []CarRegister
	if err := cursor.All(ctx, &registers); err != nil {
		return nil, 0, fmt.Errorf("error decodificando registros: %v", err)
	}

	// Calcular el total de Amount
	var total float64
	for _, r := range registers {
		if !r.Paid {
			total += r.Amount
		}
	}

	return registers, total, nil
}

func (s *store) GetCarsByOwner(userID primitive.ObjectID) ([]Car, error) {
	collection := s.database.Collection("cars")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{
		"owner": userID,
	}

	cursor, err := collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("error buscando autos: %v", err)
	}
	defer cursor.Close(ctx)

	var cars []Car
	if err := cursor.All(ctx, &cars); err != nil {
		return nil, fmt.Errorf("error decodificando autos: %v", err)
	}

	return cars, nil
}

func (s *store) GetUserBasicInfo(userID primitive.ObjectID) (string, string, string, error) {
	collection := s.database.Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Solo traemos los campos necesarios
	projection := bson.M{
		"firstName": 1,
		"lastName":  1,
		"email":     1,
	}

	filter := bson.M{"_id": userID}

	var result struct {
		FirstName string `bson:"firstName"`
		LastName  string `bson:"lastName"`
		Email     string `bson:"email"`
	}

	err := collection.FindOne(ctx, filter, options.FindOne().SetProjection(projection)).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return "", "", "", fmt.Errorf("usuario no encontrado")
		}
		return "", "", "", fmt.Errorf("error buscando usuario: %v", err)
	}

	return result.FirstName, result.LastName, result.Email, nil
}

func (s *store) GetCarRegistersTotalBalanceByOwner(userID primitive.ObjectID) (float64, error) {
	collection := s.database.Collection("car_registers")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Filtro por propietario del carro
	filter := bson.M{
		"car.owner": userID,
	}

	cursor, err := collection.Find(ctx, filter)
	if err != nil {
		return 0, fmt.Errorf("error buscando registros: %v", err)
	}
	defer cursor.Close(ctx)

	var registers []CarRegister
	if err := cursor.All(ctx, &registers); err != nil {
		return 0, fmt.Errorf("error decodificando registros: %v", err)
	}

	// Calcular el total de Amount
	var total float64
	for _, r := range registers {
		total += r.Amount
	}

	return total, nil
}
