namespace zivillian.ldap
{
    public enum ResultCode
    {
        /* ENUMERATED {
         *           success                      (0),
         *           operationsError              (1),
         *           protocolError                (2),
         *           timeLimitExceeded            (3),
         *           sizeLimitExceeded            (4),
         *           compareFalse                 (5),
         *           compareTrue                  (6),
         *           authMethodNotSupported       (7),
         *           strongerAuthRequired         (8),
         *  -- 9 reserved --
         *           referral                     (10),
         *           adminLimitExceeded           (11),
         *           unavailableCriticalExtension (12),
         *           confidentialityRequired      (13),
         *           saslBindInProgress           (14),
         *           noSuchAttribute              (16),
         *           undefinedAttributeType       (17),
         *           inappropriateMatching        (18),
         *           constraintViolation          (19),
         *           attributeOrValueExists       (20),
         *           invalidAttributeSyntax       (21),
         *  -- 22-31 unused --
         *           noSuchObject                 (32),
         *           aliasProblem                 (33),
         *           invalidDNSyntax              (34),
         *  -- 35 reserved for undefined isLeaf --
         *           aliasDereferencingProblem    (36),
         *  -- 37-47 unused --
         *           inappropriateAuthentication  (48),
         *           invalidCredentials           (49),
         *           insufficientAccessRights     (50),
         *           busy                         (51),
         *           unavailable                  (52),
         *           unwillingToPerform           (53),
         *           loopDetect                   (54),
         *  -- 55-63 unused --
         *           namingViolation              (64),
         *           objectClassViolation         (65),
         *           notAllowedOnNonLeaf          (66),
         *           notAllowedOnRDN              (67),
         *           entryAlreadyExists           (68),
         *           objectClassModsProhibited    (69),
         *  -- 70 reserved for CLDAP --
         *           affectsMultipleDSAs          (71),
         *  -- 72-79 unused --
         *           other                        (80),
         *           ...  },
         */
        /// <summary>
        /// Indicates the successful completion of an operation
        /// </summary>
        Success                      = 0,
        /// <summary>
        /// Indicates that the operation is not properly sequenced with
        /// relation to other operations (of same or different type).
        /// </summary>
        OperationsError              = 1,
        /// <summary>
        /// Indicates the server received data that is not well-formed.
        /// <remarks>
        /// For Bind operation only, this code is also used to indicate
        /// that the server does not support the requested protocol
        /// version.
        ///
        /// For Extended operations only, this code is also used to
        /// indicate that the server does not support (by design or
        /// configuration) the Extended operation associated with the
        /// requestName.
        ///
        /// For request operations specifying multiple controls, this may
        /// be used to indicate that the server cannot ignore the order
        /// of the controls as specified, or that the combination of the
        /// specified controls is invalid or unspecified.
        /// </remarks>
        /// </summary>
        ProtocolError                = 2,
        /// <summary>
        /// Indicates that the time limit specified by the client was
        /// exceeded before the operation could be completed.
        /// </summary>
        TimeLimitExceeded            = 3,
        /// <summary>
        /// Indicates that the size limit specified by the client was
        /// exceeded before the operation could be completed.
        /// </summary>
        SizeLimitExceeded            = 4,
        /// <summary>
        /// Indicates that the Compare operation has successfully
        /// completed and the assertion has evaluated to FALSE or
        /// Undefined.
        /// </summary>
        CompareFalse                 = 5,
        /// <summary>
        /// Indicates that the Compare operation has successfully
        /// completed and the assertion has evaluated to TRUE.
        /// </summary>
        CompareTrue                  = 6,
        /// <summary>
        /// Indicates that the authentication method or mechanism is not
        /// supported.
        /// </summary>
        AuthMethodNotSupported       = 7,
        /// <summary>
        /// Indicates the server requires strong(er) authentication in
        /// order to complete the operation.
        /// <remarks>
        /// When used with the Notice of Disconnection operation, this
        /// code indicates that the server has detected that an
        /// established security association between the client and
        /// server has unexpectedly failed or been compromised.
        /// </remarks>
        /// </summary>
        StrongerAuthRequired         = 8,
        /// <summary>
        /// Indicates that a referral needs to be chased to complete the
        /// operation
        /// </summary>
        Referral                     = 10,
        /// <summary>
        /// Indicates that an administrative limit has been exceeded.
        /// </summary>
        AdminLimitExceeded           = 11,
        /// <summary>
        /// Indicates a critical control is unrecognized
        /// </summary>
        UnavailableCriticalExtension = 12,
        /// <summary>
        /// Indicates that data confidentiality protections are required.
        /// </summary>
        ConfidentialityRequired      = 13,
        /// <summary>
        /// Indicates the server requires the client to send a new bind
        /// request, with the same SASL mechanism, to continue the
        /// authentication process
        /// </summary>
        SaslBindInProgress           = 14,
        /// <summary>
        /// Indicates that the named entry does not contain the specified
        /// attribute or attribute value.
        /// </summary>
        NoSuchAttribute              = 16,
        /// <summary>
        /// Indicates that a request field contains an unrecognized
        /// attribute description.
        /// </summary>
        UndefinedAttributeType       = 17,
        /// <summary>
        /// Indicates that an attempt was made (e.g., in an assertion) to
        /// use a matching rule not defined for the attribute type
        /// concerned.
        /// </summary>
        InappropriateMatching        = 18,
        /// <summary>
        /// Indicates that the client supplied an attribute value that
        /// does not conform to the constraints placed upon it by the
        /// data model.
        /// <remarks>
        /// For example, this code is returned when multiple values are
        /// supplied to an attribute that has a SINGLE-VALUE constraint.
        /// </remarks>
        /// </summary>
        ConstraintViolation          = 19,
        /// <summary>
        /// Indicates that the client supplied an attribute or value to
        /// be added to an entry, but the attribute or value already
        /// exists.
        /// </summary>
        AttributeOrValueExists       = 20,
        /// <summary>
        /// Indicates that a purported attribute value does not conform
        /// to the syntax of the attribute.
        /// </summary>
        InvalidAttributeSyntax       = 21,
        /// <summary>
        /// Indicates that the object does not exist in the DIT.
        /// </summary>
        NoSuchObject                 = 32,
        /// <summary>
        /// Indicates that an alias problem has occurred.  For example,
        /// the code may used to indicate an alias has been dereferenced
        /// that names no object.
        /// </summary>
        AliasProblem                 = 33,
        /// <summary>
        /// Indicates that an LDAPDN or RelativeLDAPDN field (e.g., search
        /// base, target entry, ModifyDN newrdn, etc.) of a request does
        /// not conform to the required syntax or contains attribute
        /// values that do not conform to the syntax of the attribute's
        /// type.
        /// </summary>
        InvalidDnSyntax              = 34,
        /// <summary>
        /// Indicates that a problem occurred while dereferencing an
        /// alias.  Typically, an alias was encountered in a situation
        /// where it was not allowed or where access was denied.
        /// </summary>
        AliasDereferencingProblem    = 36,
        /// <summary>
        /// Indicates the server requires the client that had attempted
        /// to bind anonymously or without supplying credentials to
        /// provide some form of credentials.
        /// </summary>
        InappropriateAuthentication  = 48,
        /// <summary>
        /// Indicates that the provided credentials (e.g., the user's name
        /// and password) are invalid.
        /// </summary>
        InvalidCredentials           = 49,
        /// <summary>
        /// Indicates that the client does not have sufficient access
        /// rights to perform the operation.
        /// </summary>
        InsufficientAccessRights     = 50,
        /// <summary>
        /// Indicates that the server is too busy to service the
        /// operation.
        /// </summary>
        Busy                         = 51,
        /// <summary>
        /// Indicates that the server is shutting down or a subsystem
        /// necessary to complete the operation is offline.
        /// </summary>
        Unavailable                  = 52,
        /// <summary>
        /// Indicates that the server is unwilling to perform the
        /// operation.
        /// </summary>
        UnwillingToPerform           = 53,
        /// <summary>
        /// Indicates that the server has detected an internal loop (e.g.,
        /// while dereferencing aliases or chaining an operation).
        /// </summary>
        LoopDetect                   = 54,
        /// <summary>
        /// Indicates that the entry's name violates naming restrictions.
        /// </summary>
        NamingViolation              = 64,
        /// <summary>
        /// Indicates that the entry violates object class restrictions.
        /// </summary>
        ObjectClassViolation         = 65,
        /// <summary>
        /// Indicates that the operation is inappropriately acting upon a
        /// non-leaf entry.
        /// </summary>
        NotAllowedOnNonLeaf          = 66,
        /// <summary>
        /// Indicates that the operation is inappropriately attempting to
        /// remove a value that forms the entry's relative distinguished
        /// name.
        /// </summary>
        NotAllowedOnRdn              = 67,
        /// <summary>
        /// Indicates that the request cannot be fulfilled (added, moved,
        /// or renamed) as the target entry already exists.
        /// </summary>
        EntryAlreadyExists           = 68,
        /// <summary>
        /// Indicates that an attempt to modify the object class(es) of
        /// an entry's 'objectClass' attribute is prohibited.
        ///<remarks>
        /// For example, this code is returned when a client attempts to
        /// modify the structural object class of an entry.
        /// </remarks>>
        /// </summary>
        ObjectClassModsProhibited    = 69,
        /// <summary>
        /// Indicates that the operation cannot be performed as it would
        /// affect multiple servers (DSAs).
        /// </summary>
        AffectsMultipleDsAs          = 71,
        /// <summary>
        /// Indicates the server has encountered an internal error.
        /// </summary>
        Other                        = 80
    }
}