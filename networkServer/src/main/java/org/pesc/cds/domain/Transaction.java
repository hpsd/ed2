/*
 * Copyright (c) 2017. California Community Colleges Technology Center
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.pesc.cds.domain;

import org.pesc.cds.model.TransactionStatus;

import java.sql.Timestamp;


public class Transaction {
	private Integer id;

	private Integer recipientId;

	private Integer senderId;

	private Integer signerId;

	private Integer senderTransactionId;

	private String fileFormat;

	private String documentType;

	private String department;

	private Long fileSize = 0l;

	private String filePath;

	private String requestFilePath;

	//The path to the PESC functional acknowledgement file, if there is one.
	private String ackFilePath;

	private String ackURL;

	private String operation;

	private Timestamp occurredAt;

	private Timestamp acknowledgedAt;

	private String error;

	private String message;

	private TransactionStatus status;

	private Boolean acknowledged = false;

	public Transaction() {}

	public Integer getId() {
		return id;
	}

	public void setId(final Integer id) {
		this.id = id;
	}

	public Integer getRecipientId() {
		return recipientId;
	}

	public void setRecipientId(final Integer recipientId) {
		this.recipientId = recipientId;
	}

	public Integer getSenderId() {
		return senderId;
	}

	public void setSenderId(final Integer senderId) {
		this.senderId = senderId;
	}

	public String getFileFormat() {
		return fileFormat;
	}

	public void setFileFormat(final String fileFormat) {
		this.fileFormat = fileFormat;
	}

	public String getDocumentType() {
		return documentType;
	}

	public void setDocumentType(final String documentType) {
		this.documentType = documentType;
	}

	public String getDepartment() {
		return department;
	}

	public void setDepartment(final String department) {
		this.department = department;
	}

	public Long getFileSize() {
		return fileSize;
	}

	public void setFileSize(final Long fileSize) {
		this.fileSize = fileSize;
	}

	public String getFilePath() {
		return filePath;
	}

	public void setFilePath(final String filePath) {
		this.filePath = filePath;
	}

	public String getRequestFilePath() {
		return requestFilePath;
	}

	public void setRequestFilePath(final String requestFilePath) {
		this.requestFilePath = requestFilePath;
	}

	public String getOperation() {
		return operation;
	}

	public void setOperation(final String operation) {
		this.operation = operation;
	}

	public Timestamp getOccurredAt() {
		return occurredAt;
	}

	public void setOccurredAt(final Timestamp occurredAt) {
		this.occurredAt = occurredAt;
	}

	public Timestamp getAcknowledgedAt() {
		return acknowledgedAt;
	}

	public void setAcknowledgedAt(final Timestamp acknowledgedAt) {
		this.acknowledgedAt = acknowledgedAt;
	}

	public String getError() {
		return error;
	}

	public void setError(final String error) {
		this.error = error;
	}

	public Boolean getAcknowledged() {
		return acknowledged;
	}

	public void setAcknowledged(final Boolean acknowledged) {
		this.acknowledged = acknowledged;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(final String message) {
		this.message = message;
	}

	public TransactionStatus getStatus() {
		return status;
	}

	public void setStatus(final TransactionStatus status) {
		this.status = status;
	}

	public String getAckURL() {
		return ackURL;
	}

	public void setAckURL(final String ackURL) {
		this.ackURL = ackURL;
	}

	public Integer getSenderTransactionId() {
		return senderTransactionId;
	}

	public void setSenderTransactionId(final Integer senderTransactionId) {
		this.senderTransactionId = senderTransactionId;
	}

	public Integer getSignerId() {
		return signerId;
	}

	public void setSignerId(final Integer signerId) {
		this.signerId = signerId;
	}

	public String getAckFilePath() {
		return ackFilePath;
	}

	public void setAckFilePath(final String ackFilePath) {
		this.ackFilePath = ackFilePath;
	}

}
