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

package org.pesc.cds.web;

import com.google.common.base.Preconditions;
import com.google.common.collect.Maps;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.Authorization;
import io.swagger.annotations.AuthorizationScope;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.pesc.cds.domain.Transaction;
import org.pesc.cds.model.EndpointMode;
import org.pesc.cds.model.SchoolCodeType;
import org.pesc.cds.model.TransactionStatus;
import org.pesc.cds.model.TranscriptRequestBuilder;
//import org.pesc.cds.repository.TransactionService;
import org.pesc.cds.service.FileProcessorService;
import org.pesc.cds.service.OrganizationService;
import org.pesc.cds.service.PKIService;
import org.pesc.cds.utils.DocumentUtils;
import org.pesc.sdk.core.coremain.v1_14.DocumentTypeCodeType;
import org.pesc.sdk.core.coremain.v1_14.TransmissionTypeType;
import org.pesc.sdk.message.documentinfo.v1_0.DocumentTypeCode;
import org.pesc.sdk.message.transcriptrequest.v1_4.TranscriptRequest;
import org.pesc.sdk.sector.academicrecord.v1_9.ReleaseAuthorizedMethodType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.oxm.Marshaller;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;
import org.xml.sax.SAXException;

import javax.annotation.Resource;
import javax.naming.OperationNotSupportedException;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.WebApplicationException;
import java.io.*;
import java.security.PublicKey;
import java.sql.Timestamp;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;

;

@RestController
@RequestMapping(value = "api/v1/documents")
@Api(tags = "Documents", description = "Manage Documents.")
public class DocumentController {

    private static final Log log = LogFactory.getLog(DocumentController.class);

    @Value("${directory.server.base.url}")
    private String directoryServer;

    @Value("${networkServer.id}")
    private String localServerId; // signer_id

    @Value("${networkServer.webServiceURL}")
    private String localServerWebServiceURL; // AckURL

    @Value("${networkServer.inbox.path}")
    private String localServerInboxPath;

    @Value("${api.organization}")
    private String organizationApiPath;

    @Value("${api.endpoints}")
    private String endpointsApiPath;

    @Value("${authentication.oauth.accessTokenUri}")
    private String accessTokenUri;

    @Autowired
    private PKIService pkiService;

    @Autowired
    private FileProcessorService fileProcessorService;

    @Resource(name = "transcriptRequestMarshaller")
    private Marshaller transcriptRequestMarshaller;

    @Resource(name = "documentInfoMarshaller")
    private Marshaller documentInfoMarshaller;

    @Autowired
    private OrganizationService organizationService;

    @Qualifier("directoryServerClient")
    @Autowired
    private RestTemplate directoryServerClient;

    @Autowired
    @Qualifier("myRestTemplate")
    private OAuth2RestOperations restTemplate;

    private String getPEMPublicKeyByOrgID(final Integer orgID) {
        StringBuilder uri = new StringBuilder(directoryServer + "/services/rest/v1/organizations/" + orgID + "/public-key");
        String pemPublicKey = null;
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(org.springframework.http.MediaType.TEXT_HTML));

        ResponseEntity<String> response = directoryServerClient.getForEntity(uri.toString(),
                String.class, new HttpEntity<String>(headers));

        if (response.getStatusCodeValue() == 200) {

            if (response.getStatusCodeValue() == 200) {
                pemPublicKey = response.getBody();
            }
        }

        return pemPublicKey;
    }

    private String getEndpointURIForSchool(final String orgID,
            final String documentFormat,
            final String documentType,
            final String department,
            final EndpointMode mode) throws JSONException {

        return organizationService.getEndpointForOrg(Integer.valueOf(orgID), documentFormat, documentType, department, mode);
    }

    /**
     * @param multipartFile
     * @param fileFormat
     * @param documentType
     * @param department
     * @param sourceSchoolCode
     * @param sourceSchoolCodeType
     * @param destinationSchoolCode
     * @param destinationSchoolCodeType
     * @param trStudentRelease
     * @param trStudentReleasedMethod
     * @param studentBirthDate
     * @param trStudentFirstName
     * @param trStudentMiddleName
     * @param trStudentLastName
     * @param trStudentEmail
     * @param trStudentPartialSsn
     * @param trStudentCurrentlyEnrolled
     * @return
     * @throws JSONException
     */
    @RequestMapping(value = "/outbox", method = RequestMethod.POST)
    @ResponseBody
    public void sendFile(
            @RequestParam(value = "tran_id", required = true) final String transactionId,
            @RequestParam(value = "dest_id", required = true) final String recipientId,
            @RequestParam(value = "source_id", required = true) final String senderId,
            @RequestParam(value = "file") final MultipartFile multipartFile,
            @RequestParam(value = "file_format", required = true) final String fileFormat,
            @RequestParam(value = "document_type", required = false) final String documentType,
            @RequestParam(value = "department", required = false) final String department,
            @RequestParam(value = "source_school_code", required = false) final String sourceSchoolCode,
            @RequestParam(value = "source_school_code_type", required = false) final String sourceSchoolCodeType,
            @RequestParam(value = "source_school_name", required = false) final String sourceSchoolName,
            @RequestParam(value = "source_school_street", required = false) final String sourceSchoolStreet,
            @RequestParam(value = "source_school_city", required = false) final String sourceSchoolCity,
            @RequestParam(value = "source_school_state", required = false) final String sourceSchoolState,
            @RequestParam(value = "source_school_zip", required = false) final String sourceSchoolZip,
            @RequestParam(value = "source_school_phone", required = false) final String sourceSchoolPhone,
            @RequestParam(value = "source_school_email", required = false) final String sourceSchoolEmail,
            @RequestParam(value = "destination_school_code", required = true) final String destinationSchoolCode,
            @RequestParam(value = "destination_school_code_type", required = true) final String destinationSchoolCodeType,
            @RequestParam(value = "destination_school_name", required = true) final String destinationSchoolName,
            @RequestParam(value = "student_release", required = false) final Boolean trStudentRelease,
            @RequestParam(value = "student_released_method", required = false) final String trStudentReleasedMethod,
            @RequestParam(value = "student_birth_date", required = false) final String studentBirthDate,
            @RequestParam(value = "student_first_name", required = false) final String trStudentFirstName,
            @RequestParam(value = "student_middle_name", required = false) final String trStudentMiddleName,
            @RequestParam(value = "student_last_name", required = false) final String trStudentLastName,
            @RequestParam(value = "student_email", required = false) final String trStudentEmail,
            @RequestParam(value = "student_partial_ssn", required = false) final String trStudentPartialSsn,
            @RequestParam(value = "student_currently_enrolled", required = false) final Boolean trStudentCurrentlyEnrolled) throws JSONException {

        if (!multipartFile.isEmpty()) {
            throw new IllegalArgumentException("No file was present in the upload.");
        }

        String endpointURI = getEndpointURIForSchool(transactionId,
                fileFormat,
                documentType,
                department,
                EndpointMode.LIVE);

        if (endpointURI == null) {
            // String error = ErrorUtils.getNoEndpointFoundMessage(destinationId,
            // fileFormat, documentType, department);
            // throw new IllegalArgumentException(error);
        }

        try {

            // transcript request

            boolean createTranscriptRequest = !"PESCXML".equals(fileFormat);
            TranscriptRequest transcriptRequest;
            if (createTranscriptRequest) {

                transcriptRequest = createTranscriptRequest(transactionId, recipientId, fileFormat, documentType, sourceSchoolCode,
                        sourceSchoolCodeType,
                        sourceSchoolName, sourceSchoolStreet, sourceSchoolCity, sourceSchoolZip, sourceSchoolEmail, destinationSchoolCode,
                        destinationSchoolCodeType, destinationSchoolName, trStudentRelease, trStudentReleasedMethod, studentBirthDate,
                        trStudentFirstName,
                        trStudentMiddleName, trStudentLastName, trStudentEmail, trStudentPartialSsn, trStudentCurrentlyEnrolled);

                // transcriptRequestMarshaller.marshal(transcriptRequest, new //
                // StreamResult(requestFile));
            }
            // transcript request

            LinkedMultiValueMap<String, Object> map = new LinkedMultiValueMap<>();
            map.add("recipient_id", recipientId);
            map.add("sender_id", senderId);
            map.add("signer_id", localServerId);
            map.add("file_format", fileFormat);
            map.add("document_type", documentType);
            map.add("department", department);
            map.add("transaction_id", transactionId);
            map.add("ack_url", localServerWebServiceURL);
            map.add("file", new FileSystemResource("xx"));
            map.add("signature", new ByteArrayResource(new byte[] {}) {
                @Override
                public String getFilename() {
                    return "signature.dat";
                }
            });
            if (createTranscriptRequest) {
                map.add("transcript_request_file", new FileSystemResource(""));
            }

            org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
            headers.setContentType(org.springframework.http.MediaType.MULTIPART_FORM_DATA);

            ResponseEntity<String> response = restTemplate.exchange(endpointURI, HttpMethod.POST, new org.springframework.http.HttpEntity<Object>(map,
                    headers), String.class);

            log.info(response.getStatusCode().getReasonPhrase());

        } catch (ResourceAccessException e) {

            // Force the OAuth client to retrieve the token again whenever it is used again.

            restTemplate.getOAuth2ClientContext().setAccessToken(null);

            // tx.setError(e.getMessage());
            // transactionService.update(tx);

            log.error(e);
            throw new IllegalArgumentException(e);

        } catch (Exception e) {

            log.error(e);
            // tx.setError(e.getMessage());
            // transactionService.update(tx);

            throw new IllegalArgumentException(e);

        }

        // return tx;
    }

    private TranscriptRequest createTranscriptRequest(final String transactionId, final String recipientId, final String fileFormat,
            final String documentType,
            final String sourceSchoolCode, final String sourceSchoolCodeType, final String sourceSchoolName, final String sourceSchoolStreet,
            final String sourceSchoolCity, final String sourceSchoolZip, final String sourceSchoolEmail, final String destinationSchoolCode,
            final String destinationSchoolCodeType, final String destinationSchoolName, final Boolean trStudentRelease,
            final String trStudentReleasedMethod,
            final String studentBirthDate, final String trStudentFirstName, final String trStudentMiddleName, final String trStudentLastName,
            final String trStudentEmail, final String trStudentPartialSsn, final Boolean trStudentCurrentlyEnrolled) {
        TranscriptRequest transcriptRequest;
        org.pesc.sdk.sector.academicrecord.v1_9.ObjectFactory academicRecordObjectFactory =
            new org.pesc.sdk.sector.academicrecord.v1_9.ObjectFactory();
        DocumentTypeCodeType trDocumentTypeCode = DocumentTypeCodeType.STUDENT_REQUEST;
        TransmissionTypeType trTransmissionType = TransmissionTypeType.ORIGINAL;

        // source
        Map<SchoolCodeType, String> trSourceSchoolCodes = Maps.newHashMap();
        Map<SchoolCodeType, String> trStudentSchoolCodes = Maps.newHashMap();
        trSourceSchoolCodes.put(SchoolCodeType.EDEXCHANGE, localServerId);
        Preconditions.checkArgument(StringUtils.isNotBlank(sourceSchoolCode), "Source School Code is required");
        Preconditions.checkArgument(StringUtils.isNotBlank(sourceSchoolCodeType), "Source School Code Type is required");
        SchoolCodeType srcSchoolCodeType = SchoolCodeType.valueOf(sourceSchoolCodeType);
        trSourceSchoolCodes.put(srcSchoolCodeType, sourceSchoolCode);
        trStudentSchoolCodes.put(srcSchoolCodeType, sourceSchoolCode);

        // destination
        Map<SchoolCodeType, String> trDestinationSchoolCodes = Maps.newHashMap();
        trDestinationSchoolCodes.put(SchoolCodeType.valueOf(destinationSchoolCodeType), destinationSchoolCode);
        trDestinationSchoolCodes.put(SchoolCodeType.EDEXCHANGE, String.valueOf(recipientId));

        // document
        DocumentTypeCode trDocumentType = null;
        try {
            trDocumentType = DocumentTypeCode.fromValue(documentType);
        } catch (IllegalArgumentException e) {
            trDocumentType = DocumentTypeCode.OTHER;
        }
        // student
        DateFormat dateFormat = new SimpleDateFormat("MM/dd/yyyy", Locale.ENGLISH);
        Date trStudentDOB = null;
        try {
            if (studentBirthDate != null) {
                trStudentDOB = dateFormat.parse(studentBirthDate);
            }
        } catch (Exception e) {
        }
        return new TranscriptRequestBuilder()
                .documentInfoMarshaller(documentInfoMarshaller)
                .documentID(transactionId)
                .documentTypeCode(trDocumentTypeCode)
                .transmissionType(trTransmissionType)
                .requestTrackingID(transactionId)
                .sourceSchoolCodes(trSourceSchoolCodes)
                .sourceOrganizationNames(Arrays.asList(new String[] { sourceSchoolName }))
                .sourceOrganizationAddressLines(Arrays.asList(new String[] { sourceSchoolStreet }))
                .sourceOrganizationCity(sourceSchoolCity)
                // .sourceOrganizationStateProvinceCode(sourceSchoolState)
                .sourceOrganizationPostalCode(sourceSchoolZip)
                // .sendersPhone(sourceSchoolPhone)
                .sendersEmail(sourceSchoolEmail)
                .destinationSchoolCodes(trDestinationSchoolCodes)
                .destinationOrganizationNames(Arrays.asList(new String[] { destinationSchoolName }))
                .parchmentDocumentTypeCode(trDocumentType)
                .fileName("")
                .documentFormat(fileFormat)
                .studentRelease(trStudentRelease)
                .studentReleasedMethod(ReleaseAuthorizedMethodType.valueOf(trStudentReleasedMethod))
                .studentBirthDate(trStudentDOB)
                .studentFirstName(trStudentFirstName)
                .studentLastName(trStudentLastName)
                .studentSchoolName(sourceSchoolName)
                .studentSchoolCodes(trStudentSchoolCodes)
                .studentMiddleNames(Arrays.asList(trStudentMiddleName))
                .studentEmail(trStudentEmail)
                .studentPartialSsn(trStudentPartialSsn)
                .studentCurrentlyEnrolled(trStudentCurrentlyEnrolled)
                .build();
    }

    /**
     * When another network server sends a file
     *
     * @param recipientId
     *            In this case this is the network server that we need to send the
     *            response to
     * @param multipartFile
     *            The transferred file
     * @param fileFormat
     *            The expected format of the file
     * @param transactionId
     *            This is the identifier of the transaction record from the sending
     *            network server, we send it back
     * @param ackURL
     *            This is the url to the network server that we will send the
     *            response back to
     */
    @RequestMapping(value = "/inbox", method = RequestMethod.POST)
    @PreAuthorize("hasRole('ROLE_NETWORK_SERVER') OR hasRole('ROLE_SUPERUSER')")
    @ApiOperation(value = "Upload a document.", authorizations = {
        @Authorization(value = "oauth", scopes = { @AuthorizationScope(scope = "read_inbox,write_inbox", description = "OAuth 2.0") })
    })
    public void receiveFile(
            @RequestParam(value = "recipient_id", required = false) final Integer recipientId,
            @RequestParam(value = "sender_id", required = false) final Integer senderId,
            @RequestParam(value = "signer_id", required = false) final Integer signerId,
            @RequestParam(value = "file") final MultipartFile multipartFile,
            @RequestParam(value = "signature") final MultipartFile signatureFile,
            @RequestParam(value = "file_format", required = false) final String fileFormat,
            @RequestParam(value = "document_type", required = false) final String documentType,
            @RequestParam(value = "department", required = false) final String department,
            @RequestParam(value = "transaction_id", required = false) final Integer transactionId,
            @RequestParam(value = "ack_url", required = false) final String ackURL,
            @RequestParam(value = "transcript_request_file", required = false) final MultipartFile transcriptRequestFile,
            final HttpServletRequest request) throws SAXException, IOException, OperationNotSupportedException {

        log.info(request.getRequestURI().toString());

        log.debug(String.format("received file from network server " + recipientId));

        if (multipartFile == null || signatureFile == null) {
            log.error("Incorrect number of file uploaded.  Is the digital signature file present?");
            throw new WebApplicationException("A file and it's digital signature are required.");
        }

        Transaction tx = new Transaction();
        // we need the directoryId for this organization in the organizations table
        tx.setRecipientId(recipientId);
        tx.setSenderId(senderId);
        tx.setSignerId(signerId);
        tx.setSenderTransactionId(transactionId);
        tx.setFileFormat(fileFormat);
        tx.setFileSize(multipartFile.getSize());
        tx.setDepartment(department);
        tx.setDocumentType(documentType);
        tx.setOperation("RECEIVE");
        Timestamp occurredAt = new Timestamp(Calendar.getInstance().getTimeInMillis());
        tx.setOccurredAt(occurredAt);
        tx.setAcknowledgedAt(occurredAt);
        tx.setAcknowledged(true);
        tx.setStatus(TransactionStatus.FAILURE);

        if (!StringUtils.isEmpty(ackURL)) {
            tx.setAckURL(ackURL);
        }

        File inboxDirectory = new File(localServerInboxPath);
        if (!inboxDirectory.exists() && !inboxDirectory.mkdirs()) {
            throw new RuntimeException("Failed to create directory " + inboxDirectory.getAbsolutePath());
        }

        try {

            String fileName = multipartFile.getOriginalFilename();
            File uploadedFile = new File(inboxDirectory, fileName);
            byte[] bytes = multipartFile.getBytes();

            String requestFileName = null;
            File requestFile = null;
            byte[] requestFileBytes = null;
            if (transcriptRequestFile != null) {
                requestFileName = transcriptRequestFile.getOriginalFilename();
                requestFile = new File(inboxDirectory, requestFileName);
                requestFileBytes = transcriptRequestFile.getBytes();
            }

            String pemPublicKey = getPEMPublicKeyByOrgID(signerId);

            if (pemPublicKey == null) {
                throw new IllegalArgumentException("The sender's signing certificate was invalid or non existent.  File discarded.");
            }

            PublicKey senderPublicKey = pkiService.convertPEMPublicKey(pemPublicKey);

            if (false == pkiService.verifySignature(multipartFile.getInputStream(), signatureFile.getBytes(), senderPublicKey)) {
                throw new IllegalArgumentException("Invalid digital signature found.  File discarded.");
            }

            File fp = uploadedFile.getParentFile();
            if (!fp.exists() && !fp.mkdirs()) {
                tx.setError("Could not create directory: " + fp);
            } else {
                try {
                    if (!uploadedFile.createNewFile()) {
                        tx.setError(String.format("file %s already exists", multipartFile.getOriginalFilename()));
                    } else {
                        tx.setFilePath(uploadedFile.getPath());
                        BufferedOutputStream stream = new BufferedOutputStream(new FileOutputStream(uploadedFile));
                        stream.write(bytes);
                        stream.close();

                        // Now save the transcript request file if it exists.
                        if (requestFile != null) {
                            if (!requestFile.createNewFile()) {
                                String message = tx.getError() != null ? tx.getError() : "";
                                tx.setError(message + ". " + String.format("file %s already exists", requestFileName));
                            } else {
                                tx.setRequestFilePath(requestFile.getPath());
                                BufferedOutputStream stream2 = new BufferedOutputStream(new FileOutputStream(requestFile));
                                stream2.write(requestFileBytes);
                                stream2.close();
                                tx.setStatus(TransactionStatus.SUCCESS);
                            }
                        } else {
                            tx.setStatus(TransactionStatus.SUCCESS);
                        }
                    }

                    if (fileFormat.equalsIgnoreCase("PESCXML")) {
                        DocumentUtils.validate(documentType, multipartFile.getInputStream());
                    }

                } catch (IOException ioex) {
                    tx.setMessage(ioex.getMessage());
                    tx.setError(ioex.getMessage());
                }
            }
        } catch (Exception ex) {
            log.error("Failed to process inbound document.", ex);
            tx.setMessage(ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage());
            tx.setError(ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage());
            tx.setStatus(TransactionStatus.FAILURE);
        } finally {
            // transactionService.update(tx);
        }

        fileProcessorService.deliverFile(tx);

    }

}
