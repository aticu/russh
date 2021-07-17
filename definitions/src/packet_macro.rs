//! Defines the `ssh_packet` macro.

/// Generates a struct along with parsing and composing code for an SSH packet.
///
/// The syntax is similar to the one described in the SSH RFCs, except that the field descriptions
/// must be valid Rust identifiers and constants must be surrounded by braces.
///
/// # Examples with explanations
///
/// The ["ssh-rsa" key format](https://datatracker.ietf.org/doc/html/rfc4253#page-15) can be
/// declared as follows:
///
/// ```rust
/// # use russh_definitions::ssh_packet;
/// ssh_packet! {
///     pub struct SshRsaKey {
///         string    {b"ssh-rsa"}
///         mpint     e
///         mpint     n
///     }
/// }
/// ```
///
/// The parenthesis around the first line indicate that that part will not be stored in the final
/// struct, because it always holds a constant value, which is given in the braces.
///
/// The code above would generate the following struct:
///
/// ```rust
/// pub struct SshRsaKey {
///     pub e: num_bigint::BigInt,
///     pub n: num_bigint::BigInt,
/// }
/// ```
///
/// Additionally the [`Parse`](crate::Parse) and [`Compose`](crate::Compose) traits are
/// automatically implemented for the generated struct.
/// The parsing code automatically checks that the constant value is correct and the composing
/// function automatically outputs the correct constant value in the right place.
/// That means that constant values will not be stored in the struct.
///
/// Also note how all fields inherent the visibility from the struct itself.
/// It is not possible to specify an individual visibility for fields.
///
/// ## Lifetimes
///
/// If the struct contains one of the `string`, `name-list` or `....` (see below) types, the parsed
/// result will borrow from the input and thus requires a lifetime.
/// A lifetime named `'data` is automatically added to the struct in this case.
/// For example the [ignore message](https://datatracker.ietf.org/doc/html/rfc4253#section-11.2)
/// can be declared as follows:
///
/// ```rust
/// const SSH_MSG_IGNORE: u8 = 2;
///
/// # use russh_definitions::ssh_packet;
/// ssh_packet! {
///     struct SshMsgIgnore {
///         byte      {SSH_MSG_IGNORE}
///         string    data
///     }
/// }
/// ```
///
/// This generates the following structure:
///
/// ```rust
/// struct SshMsgIgnore<'data> {
///     data: std::borrow::Cow<'data, [u8]>,
///     _phantom_lifetime: std::marker::PhantomData<&'data ()>
/// }
/// ```
///
/// Note how the type of `data` is [`Cow<'data, [u8]>`](std::borrow::Cow) and not just
/// [`&[u8]`](slice).
/// This allows more flexibility when constructing the structure for composing, as owned data could
/// be used instead of borrowed data.
///
/// The `_phantom_lifetime` field is unfortunately required to support use cases in which all
/// fields with a lifetime are not compiled in by use of `cfg` attributes.
///
/// ## Capture the rest with `....`
///
/// `....` can be used to indicate that the rest of the input should be captured in that
/// field, as in the RFCs.
///
/// For example the
/// [channel open message](https://datatracker.ietf.org/doc/html/rfc4254#section-5.1) can be
/// declared as follows:
///
/// ```rust
/// const SSH_MSG_CHANNEL_OPEN: u8 = 90;
///
/// # use russh_definitions::ssh_packet;
/// ssh_packet! {
///     struct SshMsgChannelOpen {
///         byte      {SSH_MSG_CHANNEL_OPEN}
///         string    channel_type
///         uint32    sender_channel
///         uint32    initial_window_size
///         uint32    maximum_packet_size
///         ....      channel_type_specific_data
///     }
/// }
/// ```
///
/// This generates the following structure:
///
/// ```rust
/// struct SshMsgChannelOpen<'data> {
///     channel_type: &'data [u8],
///     sender_channel: u32,
///     initial_window_size: u32,
///     maximum_packet_size: u32,
///     // captures all data in the input after the other fields
///     channel_type_specific_data: std::borrow::Cow<'data, [u8]>,
/// }
/// ```
///
/// ## Constant sized arrays
///
/// Constant sized arrays can be declared as follows:
///
/// ```rust
/// # use russh_definitions::ssh_packet;
/// ssh_packet! {
///     struct ExampleMessage {
///         byte[16]  some_data
///     }
/// }
/// ```
///
/// This generates the following structure:
///
/// ```rust
/// struct ExampleMessage {
///     some_data: [u8; 16],
/// }
/// ```
///
/// ## Attributes
///
/// Attributes can be used on both the struct itself and any of its fields.
///
/// ```rust
/// # use russh_definitions::ssh_packet;
/// ssh_packet! {
///     /// Doc comment
///     #[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
///     struct ExampleMessage {
///         /// Field doc comment
///         #[cfg(foo)]
///         byte[16]  some_data
///         /// This doc comment isn't used, but other attributes, such as the `cfg` below still
///         /// apply in the `Parse` and `Compose` implementations
///         #[cfg(foo)]
///         string    {b"constant-string"}
///     }
/// }
/// ```
///
/// This generates the following structure:
///
/// ```rust
/// /// Doc comment
/// #[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
/// struct ExampleMessage {
///     /// Field doc comment
///     #[cfg(foo)]
///     some_data: [u8; 16],
/// }
/// ```
///
/// # Mapping of types
///
/// | SSH RFC type | Rust type                                               |
/// |--------------|---------------------------------------------------------|
/// | `byte[N]`    | [`[u8; N]`](array)                                      |
/// | `byte`       | [`u8`]                                                  |
/// | `boolean`    | [`bool`]                                                |
/// | `uint32`     | [`u32`]                                                 |
/// | `uint64`     | [`u64`]                                                 |
/// | `string`     | [`Cow<'data, [u8]>`](std::borrow::Cow)                  |
/// | `mpint`      | [`num_bigint::BigInt`]                                  |
/// | `name-list`  | [`Cow<'namelist, [Cow<'data, str>]>`](std::borrow::Cow) |
/// | `....`       | [`Cow<'data, [u8]>`](std::borrow::Cow)                  |
///
/// # Formal grammar of the macro
///
/// ```text
/// MacroContent = StructDef*
///
/// StructDef = OuterAttribute* Visibility? "struct" IDENTIFIER "{" StructField* RestField? "}"
///
/// StructField = OuterAttribute* FieldType FieldValue
///
/// FieldType = "byte[" Expression "]"
///           | "byte"
///           | "boolean"
///           | "uint32"
///           | "uint64"
///           | "string"
///           | "mpint"
///           | "name-list"
///
/// FieldValue = IDENTIFIER
///            | "{" Expression "}"
///
/// RestField = "...." IDENTIFIER
/// ```
///
/// The definitions of [`OuterAttribute`](https://doc.rust-lang.org/reference/attributes.html),
/// [`Visibility`](https://doc.rust-lang.org/reference/visibility-and-privacy.html),
/// [`IDENTIFIER`](https://doc.rust-lang.org/reference/identifiers.html) and
/// [`Expression`](https://doc.rust-lang.org/reference/expressions.html) can be found in the Rust
/// reference.
#[macro_export]
#[rustfmt::skip]
macro_rules! ssh_packet {
    ($(
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $($fields:tt)*
        }
    )*) => {
        $(
            // All of the details are documented and handled in the `ssh_packet_internal` macro.
            $crate::ssh_packet_internal!(@preprocess_type
                { $($fields)* } { $(#[$meta])* $vis $name } {} {} {}
            );
        )*
    };
}

// This macro works in two steps: preprocessing and generation.
//
// During preprocessing all of the field types and values are parsed and the corresponding types,
// parser functions, whether they include a lifetime and how they should be passed to the composer
// is recorded.
// This is done in the `@preprocess_type` invocations.
// These are interleaved with `@preprocess_field` invocations which use the information from the
// type preprocessing and the field token to either produce a constant field (`{CONST}`) or a named
// field (`name`).
// They are disambiguated through different either different types of parenthesis around the
// results.
// This allows to differentiate between them in the generation phase while keeping the order
// exactly the same as in the original invocation, even between the two kinds.
//
// After the last `@preprocess_type` invocation detects the end of the input, it invokes the
// `@generate` step, which will then use the aggregated information from the preprocessing to
// generate the final result in a single invocation.
// It is important that the whole struct is generated in a single invocation, because macros cannot
// expand to fields in a struct.
//
// This two phase approach is done to simplify parsing of different token-lengths for types and to
// ensure that no additional separators between lines are necessary.
// It also allows handling the two different field types in an elegant and transparent way.
//
// The "arguments" for each macro invocation are explained in further detail below its first
// definition.
//
// As an example consider the different macro invocations for the following input:
//
// ```rust
// ssh_packet! {
//     struct SshMsgIgnore {
//         byte      {SSH_MSG_IGNORE}
//         string    data
//     }
// }
// ```
//
// ```text
// - main invocation (of the `ssh_packet` macro, not this one) with the original input, which
//   collects some general metadata which is passed transparently down to the `@generate`
//   invocation through all intermediate invocations
// - `@preprocess_type` with "byte {SSH_MSG_IGNORE} string data" as rest input
// - `@preprocess_field` with information about the byte type and "{SSH_MSG_IGNORE} string data" as
//   rest input
// - `@preprocess_type` with "string data" as rest input
// - `@preprocess_field` with information about the string type and "data" as rest input
// - `@preprocess_type` with "" as rest input
// - `@generate` with "[{byte type info} {SSH_MSG_IGNORE}] {{string type info} data}" as input
// ```
#[macro_export]
#[rustfmt::skip]
#[doc(hidden)]
macro_rules! ssh_packet_internal {
    // `@preprocess_type` has 5 arguments:
    // - the unprocessed rest input (this gets shorter with each invocation)
    // - the meta information (attributes, visibility and name of the struct;
    //   this remains the same for each invocation)
    // - the lifetime that is currently in use (this is either { } or { 'data }, but once it was {
    //   'data } once, it will remain that way for all further invocations, as that stores whether
    //   a lifetime is needed)
    // - the namelist lifetime that is currently in use (this is either { } or { 'namelist }, but
    //   once it was { 'namelist } once, it will remain that way for all further invocations, as
    //   that stores whether a lifetime is needed)
    // - the already processed tokens from past invocations (this gets bigger with each invocation)
    //
    // It then records the type information and finally invokes `@preprocess_field` to connect the
    // type information with the correct value or name.
    //
    // The type information has the following format:
    // {
    //     attributes_of_the_field,
    //     rust_type_of_result,
    //     parser_function_for_type,
    //     writer_function_for_type,
    //     (use_ref? : use_subslice?)
    // }
    //
    // `use_ref` and `use_subslice` are recorded as idetifiers here to allow them to be used in
    // repeat expressions in the generation step.
    // This is needed to disambiguate what is being repeated.
    // Passing this information along through the parses is what allows string constants like
    // b"ssh-rsa" to be used without having to write the subslice operation in the constant,
    // because without taking a slice from them they expand to an array type.
    //
    // In addition to the type information in the block, a separate argument is used to record
    // whether the type needs a lifetime.
    //
    // This macro is also responsible for parsing the "rest catcher" at the end of the struct
    // definition: ".... rest_name"
    (@preprocess_type { $(#[$fmeta:meta])* byte[$n:expr] $($rest:tt)* }
     $meta:tt $lt:tt $nllt:tt $finished:tt) => {
        $crate::ssh_packet_internal!(@preprocess_field
            { $(#[$fmeta])*, [u8; $n],
                $crate::parse::bytes_const, $crate::write::bytes,
                (use_ref:use_subslice) }
            $meta $lt {} $nllt {} { $($rest)* } $finished
        );
    };
    (@preprocess_type { $(#[$fmeta:meta])* byte $($rest:tt)* }
     $meta:tt $lt:tt $nllt:tt $finished:tt) => {
        $crate::ssh_packet_internal!(@preprocess_field
            { $(#[$fmeta])*, u8,
                $crate::parse::byte, $crate::write::byte,
                (:) }
            $meta $lt {} $nllt {} { $($rest)* } $finished
        );
    };
    (@preprocess_type { $(#[$fmeta:meta])* boolean $($rest:tt)* }
     $meta:tt $lt:tt $nllt:tt $finished:tt) => {
        $crate::ssh_packet_internal!(@preprocess_field
            { $(#[$fmeta])*, bool,
                $crate::parse::boolean, $crate::write::boolean,
                (:) }
            $meta $lt {} $nllt {} { $($rest)* } $finished
        );
    };
    (@preprocess_type { $(#[$fmeta:meta])* uint32 $($rest:tt)* }
     $meta:tt $lt:tt $nllt:tt $finished:tt) => {
        $crate::ssh_packet_internal!(@preprocess_field
            { $(#[$fmeta])*, u32,
                $crate::parse::uint32, $crate::write::uint32,
                (:) }
            $meta $lt {} $nllt {} { $($rest)* } $finished
        );
    };
    (@preprocess_type { $(#[$fmeta:meta])* uint64 $($rest:tt)* }
     $meta:tt $lt:tt $nllt:tt $finished:tt) => {
        $crate::ssh_packet_internal!(@preprocess_field
            { $(#[$fmeta])*, u64,
                $crate::parse::uint64, $crate::write::uint64,
                (:) }
            $meta $lt {} $nllt {} { $($rest)* } $finished
        );
    };
    (@preprocess_type { $(#[$fmeta:meta])* string $($rest:tt)* }
     $meta:tt $lt:tt $nllt:tt $finished:tt) => {
        $crate::ssh_packet_internal!(@preprocess_field
            { $(#[$fmeta])*, ::std::borrow::Cow<'data, [u8]>,
                $crate::parse::string, $crate::write::string,
                (use_ref:use_subslice) }
            $meta $lt { 'data } $nllt {} { $($rest)* } $finished
        );
    };
    (@preprocess_type { $(#[$fmeta:meta])* mpint $($rest:tt)* }
     $meta:tt $lt:tt $nllt:tt $finished:tt) => {
        $crate::ssh_packet_internal!(@preprocess_field
            { $(#[$fmeta])*, num_bigint::BigInt,
                $crate::parse::mpint, $crate::write::mpint,
                (use_ref:) }
            $meta $lt {} $nllt {} { $($rest)* } $finished
        );
    };
    (@preprocess_type { $(#[$fmeta:meta])* name-list $($rest:tt)* }
     $meta:tt $lt:tt $nllt:tt $finished:tt) => {
        $crate::ssh_packet_internal!(@preprocess_field
            { $(#[$fmeta])*, ::std::borrow::Cow<'namelist, [::std::borrow::Cow<'data, str>]>,
                $crate::parse::name_list::<::std::borrow::Cow<str>>, $crate::write::name_list,
                (use_ref:) }
            $meta $lt { 'data } $nllt {'namelist } { $($rest)* } $finished
        );
    };
    (@preprocess_type { $(#[$fmeta:meta])* .... $rest_name:ident }
     $meta:tt $lt:tt { $($nllt:tt)? } $finished:tt) => {
        $crate::ssh_packet_internal!(@generate
            $meta { 'data $($nllt)?}
            $finished { $(#[$fmeta])* $rest_name }
        );
    };
    (@preprocess_type {}
     $meta:tt { $($lt:tt)? } { $($nllt:tt)? } $finished:tt) => {
        $crate::ssh_packet_internal!(@generate
            $meta { $($lt)? $($nllt)? }
            $finished {}
        );
    };
    // `@preprocess_field` has 8 arguments:
    // - the type information from the previous `@preprocess_type` invocation (see that
    //   documentation for the format of this data)
    // - the meta information (attributes, visibility and name of the struct;
    //   this remains the same for each invocation)
    // - the lifetime that was previously in use (this is either { } or { 'data })
    // - whether a lifetime is added by the type information (this is either { } or { 'data })
    // - the namelist lifetime that was previously in use (this is either { } or { 'namelist })
    // - whether a namelist lifetime is added by the type information (this is either { } or 
    //   { 'namelist })
    // - the rest of the input tokens (this gets smaller with each invocation)
    // - the already processed tokens from past invocations (this gets bigger with each invocation)
    //
    // It then records disambiguates between constants (braced expressions) and named fields
    // (identifiers), by using brackets or braces around the result in the output respectively.
    // This macro is also responsible of producing the logical OR between the old lifetime being
    // present and the new lifetime being present in case of named fields.
    // Finally it appends its results to the output calls `@preprocess_type` to continue parsing
    // the next type.
    (@preprocess_field $type:tt $meta:tt $old_lt:tt {} $old_nllt:tt {}
     { $field_name:ident $($rest:tt)* } { $($finished:tt)* }) => {
        $crate::ssh_packet_internal!(@preprocess_type { $($rest)* } $meta
            $old_lt $old_nllt
            { $($finished)* {$type $field_name}, }
        );
    };
    (@preprocess_field $type:tt $meta:tt $old_lt:tt { $new_lt:tt } $old_nllt:tt {}
     { $field_name:ident $($rest:tt)* } { $($finished:tt)* }) => {
        $crate::ssh_packet_internal!(@preprocess_type { $($rest)* } $meta
            { $new_lt } $old_nllt
            { $($finished)* {$type $field_name}, }
        );
    };
    (@preprocess_field $type:tt $meta:tt $old_lt:tt {} $old_nllt:tt { $new_nllt:tt }
     { $field_name:ident $($rest:tt)* } { $($finished:tt)* }) => {
        $crate::ssh_packet_internal!(@preprocess_type { $($rest)* } $meta
            $old_lt { $new_nllt }
            { $($finished)* {$type $field_name}, }
        );
    };
    (@preprocess_field $type:tt $meta:tt $old_lt:tt { $new_lt:tt } $old_nllt:tt { $new_nllt:tt }
     { $field_name:ident $($rest:tt)* } { $($finished:tt)* }) => {
        $crate::ssh_packet_internal!(@preprocess_type { $($rest)* } $meta
            { $new_lt } { $new_nllt }
            { $($finished)* {$type $field_name}, }
        );
    };
    (@preprocess_field $type:tt $meta:tt $old_lt:tt $new_lt:tt $old_nllt:tt $new_nllt:tt
     { {$val:expr} $($rest:tt)* } { $($finished:tt)* }) => {
        $crate::ssh_packet_internal!(@preprocess_type { $($rest)* } $meta
            $old_lt $old_nllt
            { $($finished)* [$type {$val}], }
        );
    };
    // `@preprocess_field` has 4 arguments:
    // - the meta information consisting of the struct attributes, visibility and name
    // - an optional lifetime to use in the struct and impl declarations; if a name-list is among
    //   the named fields, an additional lifetime for the name list is also present
    // - the preprocessed type information disambiguated between constants (named exc; not kept in
    //   the struct) named fields (named inc; kept in the struct); this is the output from the
    //   previous phase and the main input to this stage
    // - the optional name of the rest input catching field of the struct
    //
    // The structure used for the input $($({named_field_info})? $([constant_info])?)+ allows to
    // keep the order of the fields and constants intact for parsing, while still being able to
    // separately handle them.
    // The `+` repetition is used here to handle the case of an empty input. If a `*` repetition
    // were used, it could either be parsed as 0 repetitions of the outer macro or one repetition
    // of the outer macro with both inner macros being empty.
    (@generate { $(#[$meta:meta])* $vis:vis $name:ident } { $($lt:tt $($nllt:tt)?)? } { $(
        $({{$(#[$inc_attr:meta])*, $inc_type:ty, $inc_parser:expr, $inc_writer:expr,
            ($($inc_use_ref:ident)? : $($inc_use_subslice:ident)?)} $field_name:ident})?
        $([{$(#[$exc_attr:meta])*, $exc_type:ty, $exc_parser:expr, $exc_writer:expr,
            ($($exc_use_ref:ident)? : $($exc_use_subslice:ident)?)} {$val:expr}])?
    ),+ }
        { $($(#[$rest_attr:meta])* $rest_name:ident)? }
    ) => {
        $(#[$meta])*
        $vis struct $name<$($lt, $($nllt)?)?> {
            $(
                $(
                    $(#[$inc_attr])*
                    $vis $field_name: $inc_type,
                )?
            )*
            $(
                $(#[$rest_attr])*
                $vis $rest_name: ::std::borrow::Cow<'data, [u8]>,
            )?
            $(
                // This field is required to capture the lifetime in case all other fields with a
                // lifetime are `cfg`d away, which cannot be detected without a much more elaborate
                // mechanism.
                $vis _phantom_lifetime: ::std::marker::PhantomData<$(&$nllt)? &$lt ()>,
            )?
        }

        impl<'data $($(,$nllt: 'data)?)?> $crate::parse::Parse<'data> for $name<$($lt, $($nllt)?)?>
        {
            #[allow(unused)]
            #[allow(nonstandard_style)]
            fn parse(input: &'data [u8]) -> $crate::parse::Result<Self> {
                use $crate::parse::{ParsedValue, ParseError};
                let rest_input = input;
                $(
                    $(
                        // Parse a named field
                        $(#[$inc_attr])*
                        let ParsedValue { value: $field_name, rest_input } =
                            $inc_parser(rest_input)?;
                    )?
                    $(
                        // Parse a constant
                        $(#[$exc_attr])*
                        let ParsedValue { value: __val, rest_input } = $exc_parser(rest_input)?;
                        $(#[$exc_attr])*
                        if __val != $val {
                            return Err(ParseError::Invalid);
                        }
                    )?
                )*

                Ok(ParsedValue {
                    value: $name {
                        $(
                            $(
                                $(#[$inc_attr])*
                                $field_name: $field_name.into(),
                            )?
                        )*
                        $(
                            // Parse the rest
                            $(#[$rest_attr])*
                            $rest_name: rest_input.into(),
                        )?
                        $(
                            // The lifetimes here are fully qualified to make sure the macro knows
                            // which repetition we mean
                            _phantom_lifetime: ::std::marker::PhantomData::<$(&$nllt)? &$lt ()>,
                        )?
                    },
                    // returns the rest of the input, if no rest exists in the struct, otherwise
                    // the repetition below matches, returning &[] instead
                    rest_input: &rest_input[$({
                        let mut beginning = 0;

                        // use $rest_name, to tell the macro which repetition we mean
                        #[cfg(any($rest_name, not($rest_name)))]
                        $(#[$rest_attr])*
                        {
                            beginning = rest_input.len();
                        }

                        beginning
                    })?..]
                })
            }
        }

        impl<$($lt, $($nllt)?)?> $crate::write::Compose for $name<$($lt, $($nllt)?)?> {
            #[allow(unused)]
            #[allow(nonstandard_style)]
            fn compose(&self, output: &mut impl ::std::io::Write) -> ::std::io::Result<()> {
                $(
                    $(
                        // Write named fields
                        $(#[$inc_attr])*
                        $inc_writer(
                            // We need to use $inc_use_ref here to tell the macro which repetition
                            // we mean. This way it is expanded to a cfg-attribute that is always
                            // true, thus not affecting the argument at all.
                            // This allows adding the & in the repetition.
                            $(#[cfg(any($inc_use_ref, not($inc_use_ref)))] &)?
                            self.$field_name
                            // Ideally we'd like the repetition here to expand to `[..]`, but we
                            // need to use the $inc_use_subslice argument somewhere to let the
                            // macro know which repetition we mean.
                            // So instead we use a cfg-attribute which is always true and expands
                            // to `[0..]` in the end, which is equivalent in this case.
                            $([{ #[cfg(any($inc_use_subslice, not($inc_use_subslice)))] 0 }..])?,
                            output
                        )?;
                    )?
                    $(
                        // Write constants
                        $(#[$exc_attr])*
                        $exc_writer(
                            // We need to use $exc_use_ref here to tell the macro which repetition
                            // we mean. This way it is expanded to a cfg-attribute that is always
                            // true, thus not affecting the argument at all.
                            // This allows adding the & in the repetition.
                            $(#[cfg(any($exc_use_ref, not($exc_use_ref)))] &)?
                            $val
                            // Ideally we'd like the repetition here to expand to `[..]`, but we
                            // need to use the $exc_use_subslice argument somewhere to let the
                            // macro know which repetition we mean.
                            // So instead we use a cfg-attribute which is always true and expands
                            // to `[0..]` in the end, which is equivalent in this case.
                            $([{ #[cfg(any($exc_use_subslice, not($exc_use_subslice)))] 0 }..])?,
                            output
                        )?;
                    )?
                )*
                $(
                    // Write the rest
                    $(#[$rest_attr])*
                    $crate::write::bytes(&self.$rest_name, output)?;
                )?

                Ok(())
            }
        }
    };
}

/// This module only exists to run the doctest.
///
/// ```compile_fail
/// mod inner {
///     use russh_definitions::ssh_packet;
///
///     ssh_packet! {
///         #[derive(Debug, PartialEq, Eq)]
///         struct Packet {
///             boolean   some_field
///         }
///     }
/// }
///
/// let _ = inner::Packet { some_field: true };
/// ```
mod struct_privacy_works {}
