// Package fsscan reads configuration files at known paths under a user's home directory, and
// answers which accounts have a home worth looking in.
//
// Two jobs, because the second is what makes the first safe to attempt. A table that reads
// another account's files has to know whose home it is standing in, and it has to be unable
// to be redirected out of that home by anything the account can write.
//
// What the package guarantees:
//
//   - Every component between the home and the file is opened with symlinks refused, not
//     only the last one. A user owns their home, so they can replace any intermediate
//     directory with a link into another account's; plain O_NOFOLLOW covers the final
//     component and nothing above it. See OpenBeneath.
//   - A location a client's configuration file recorded is contained before it is used:
//     percent-decoded when it arrived as a file URL, and refused when it names a remote
//     host, a UNC share, or anything outside the home it was recorded under. See
//     ContainProjectPath, whose returned relative path is the only form a caller may open.
//   - Reads are capped in bytes and refuse a non-regular file, and on request refuse a
//     multiply-linked file or one owned by another account. Those checks are applied to the
//     descriptor that was opened rather than to the path, so a second lookup by name cannot
//     be answered with a different file. See ReadOpts and ReadBoundedUnder.
//   - A file whose content is not local is refused rather than read, because reading one is
//     a download of unbounded duration rather than a read. See ReadProjectFile.
//   - One directory listing, one level deep and capped, for the per-profile directories
//     whose names are generated and so cannot be written down in advance. See
//     ListDirNamesUnder.
//   - Failures are reported as a closed set of classes rather than as error text, so a
//     caller can say which refusal happened in a table column without republishing the path
//     or the content that caused it. See ErrClass, ClassifyError and IsExpectedAbsent.
//
// The account roster comes from osquery's own users table rather than from the filesystem.
// See ListUserHomes, and the commentary at the top of users.go for what that does and does
// not include.
//
// Platform support is asymmetric on purpose. POSIX gets iterated openat(O_NOFOLLOW); Windows
// rebuilds the same property out of os.Root, a per-component reparse-point refusal and a
// post-open identity re-check; everything else reports unsupported rather than degrading to
// an open that could be redirected without the caller being able to tell.
package fsscan
