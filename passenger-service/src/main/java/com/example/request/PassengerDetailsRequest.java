package com.example.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PassengerDetailsRequest {
	@NotBlank
	private String name;

	@NotBlank
	private String phoneNumber;

	@Email
	@NotBlank
	private String email;

	@NotBlank
	private String houseNo;

	@NotBlank
	private String city;

	@NotBlank
	private String state;

}
