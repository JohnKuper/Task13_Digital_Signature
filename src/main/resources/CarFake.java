package com.johnkuper.entity;
//this car entity is fake
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "cars")
public class Car {

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	@Column(name = "id_car")
	private int id;

	@Column(nullable = false, length = 100)
	private String name;

	@Column(nullable = false, length = 100)
	private String model;

	@Column(nullable = false, length = 100)
	private String modification;

	@Column(nullable = false, length = 30)
	private String color;

	public Car() {
	}

	public Car(String name, String model, String modification, String color) {
		this.name = name;
		this.model = model;
		this.modification = modification;
		this.color = color;
	}

	@Override
	public String toString() {
		return " Car: {id = " + id + "; name = " + name + "; model = " + model
				+ "; modification = " + modification + "; color = " + color
				+ "} ";
	}

	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getModel() {
		return model;
	}

	public void setModel(String model) {
		this.model = model;
	}

	public String getModification() {
		return modification;
	}

	public void setModification(String modification) {
		this.modification = modification;
	}

	public String getColor() {
		return color;
	}

	public void setColor(String color) {
		this.color = color;
	}

}
