// A sketch of a convenient argument parsing API for C.
// Example usage:

/*
  #include <stdio.h>

  #define MOP_IMPLEMENTATION
  #include "mop.h"

  int main(int argc, char **argv) {
    MopUsageInfo usage_infos[16];
    Mop mop = mop_begin_with_usage(argc, argv,
                                   usage_infos,
                                   sizeof usage_infos / sizeof *usage_infos);
    mop_usage_text(&mop, "Usage: ");
    mop_usage_text(&mop, argv[0] ? argv[0] : "mop_example");
    mop_usage_text(&mop, " [OPTION]... [ARG]...\n\n");
    MOP_LOOP(&mop) {
      MOP_OPT(.name = "output-file", .short_name = 'o',
              .has_arg = true, .optarg_name = "FILE",
              .help = "path of output file") {
        printf("selected output file %s\n", mop.optarg);
      }
      MOP_OPT(.name = "verbose", .short_name = 'v', .help = "verbose mode") {
        printf("increasing verbosity\n");
      }

      mop_usage_text(&mop, "\nStandard options:\n");
      MOP_OPT(.name = "help", .help = "show this help message") {
        mop_print_usage(&mop, stdout);
        exit(0);
      }
    }

    if (mop.error) {
      fprintf(stderr, "%s: %s\n", mop_error_string(mop.error), mop.erroneous_option);
      mop_print_usage(&mop, stderr);
      exit(1);
    }

    argc -= mop.argind;
    argv += mop.argind;

    printf("Remaining arguments:\n");
    for (int i = 0; i < argc; i++) {
      printf("  %s\n", argv[i]);
    }

    return 0;
  }
*/

// Options can be specified with
// MOP_OPT(.name = "long-name", .short_name = 'l', .has_arg = true,
//         .optarg_name = "THING", .help = "sufficiently long name value") {
//   ...
// }
// Where all parts are optional.
//
// They can also be specified with MOP_STR:
// MOP_STR("long-name'l:THING", "sufficiently long name value") {
//   ...
// }
// Such that each string option specifier consists of (in order) a long option
// name, an apostrophe followed by a one-character short option name, and
// a colon indicating that the option takes an argument (and all parts are
// optional).

// For options that take an argument, the argument is given in mop.optarg.
// If an error is encountered, it's given in mop.error; mop.erroneous_option
// points to the option that caused the error.
// The index of the first unprocessed argument is given in mop.argind.

// To skip usage message generation, use mop_begin instead of
// mop_begin_with_usage.
// To add text to the usage message, use mop_usage_text.
//
// Option help text can contain newlines; all lines will be indented to the same
// level. If the text starts with a newline, the help text will appear on the
// next line instead of immediately after the option.


// TODO: It's not clear that these macros do enough to justify themselves.
// Note that the library is usable without any macros.

// TODO: A handler for unknonwn options could be pretty easy to support.
// Maybe other types of error recovery too?

// TODO: This new MOP_OPT syntax is nicer than MOP_STR, but it's longer.
// Probably I should just get rid of MOP_STR entirely?

// TODO: MOP_OPT_INT64, MOP_OPT_BOOL, MOP_OPT_STRING, etc. wrappers could be
// nice for many uses, to automate simple kinds of argument parsing. They could
// also let the user do additional checking:
// MOP_OPT_INT64(&x, .name = "arbitrary-value");
// MOP_OPT_INT64(&y, .name = "constrained-value") {
//   if (y > 10) { /* error */ }
// }

// TODO: I don't really like the mop_begin_with_usage API (though I do like the
// part where it doesn't need to allocate). Maybe it should get a flag, and
// then you set the values directly on the struct? Maybe you should pass in the
// sizeof instead of numof elements, so the code to call it is shorter?

// TODO: Maybe .has_arg and .optarg_name is redundant. The presence of
// optarg_name could indicate that there's an argument, whether or not usage is
// enabled.

// TODO: It might make sense to skip printing an option if .help isn't specified,
// so people can print their own usage text instead.
// (People might also just process usage_infos themselves.)

// TODO: Maybe support GNU-style options-after-arguments?
// TODO: Maybe support getopt_long_only-style "-long-option" mode?

#if !defined MOP_H
#define MOP_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

typedef struct Mop Mop;
typedef struct MopOptInfo MopOptInfo;
typedef struct MopUsageInfo MopUsageInfo;

Mop mop_begin(int argc, char **argv);
Mop mop_begin_with_usage(int argc, char **argv, MopUsageInfo *usage_info_buf, int usage_info_buf_cap);
bool mop_next(Mop *mop);
bool mop_option(Mop *mop, MopOptInfo info);
bool mop_option_str(Mop *mop, char *opt_desc, char *help);
void mop_usage_text(Mop *mop, const char *text);
void mop_print_usage(Mop *mop, FILE *file);

#define MOP_LOOP(m) for (Mop *mop__ptr = (m); mop_next(mop__ptr); )

#if defined __cplusplus
  #define MOP_OPT(...) if (mop_option(mop__ptr, MopOptInfo{ __VA_ARGS__ }))
#else
  #define MOP_OPT(...) if (mop_option(mop__ptr, (MopOptInfo){ __VA_ARGS__ }))
#endif
#define MOP_STR(opt, help) if (mop_option_str(mop__ptr, (opt), (help)))
#define MOP_TEXT(text) mop_usage_text(mop__ptr, (text))

enum MopError {
  MopError_None = 0,
  MopError_UnknownOpt,
  MopError_MissingOptarg,
  MopError_ExtranousOptarg,
} typedef MopError;

const char *mop_error_string(MopError error);

struct MopOptInfo {
  const char *name; // Long name.

  char short_name; // 0 for no short name.
  bool has_arg;

  const char *optarg_name;
  const char *help;

  // Filled in by library.
  int name_len;
};

enum MopUsageInfoType {
  MopUsageInfoType_OptInfo,
  MopUsageInfoType_Text,
} typedef MopUsageInfoType;

struct MopUsageInfo {
  MopUsageInfoType type;
  union {
    MopOptInfo opt_info; // MopUsageInfoType_OptInfo
    const char *text;    // MopUsageInfoType_Text
  };
};

enum MopState {
  MopState_Unstarted = 0,
  MopState_GatheringUsageInfo,
  MopState_Active,
  MopState_Done,
} typedef MopState;

struct Mop {
  MopError error;
  MopState state;

  char *erroneous_option;

  char *optarg;
  int argind;

  // Index into the current short option string, e.g. "-abc". 0 if not currently
  // parsing a short option.
  int short_opt_index;

  MopUsageInfo *usage_infos;
  int usage_infos_cap;
  int usage_infos_len;

  // Are we actively processing an option? Once an option is handled this gets
  // set to false, so we can detect if an option wasn't handled.
  bool opt_active;

  // A buffer to store an erroneous_option string for short options.
  char erroneous_option_buf[3];

  // The original argc and argv, as passed to mop_begin.
  int argc;
  char **argv;
};

#endif



#if defined MOP_IMPLEMENTATION
#include <assert.h>
#include <stdlib.h>
#include <string.h>

Mop mop_begin(int argc, char **argv) {
  Mop mop = {.argc = argc, .argv = argv};
  return mop;
}

Mop mop_begin_with_usage(int argc, char **argv,
                         MopUsageInfo *usage_info_buf,
                         int usage_info_buf_cap) {
  Mop mop = {.usage_infos = usage_info_buf,
             .usage_infos_cap = usage_info_buf_cap,
             .argc = argc, .argv = argv};
  return mop;
}

bool mop_next(Mop *mop) {
  if (mop->state == MopState_Unstarted) {
    if (mop->usage_infos) {
      mop->state = MopState_GatheringUsageInfo;
      return true;
    } else {
      mop->state = MopState_Active;
    }
  }

  if (mop->state == MopState_GatheringUsageInfo) {
    // We got usage info, so switch to parsing arguments.
    mop->state = MopState_Active;
  }

  if (mop->state == MopState_Active) {
    if (mop->error) {
      mop->state = MopState_Done;
      return false;
    }
    if (mop->opt_active) {
      mop->error = MopError_UnknownOpt;
      if (mop->short_opt_index > 0) {
        char short_name = mop->argv[mop->argind][mop->short_opt_index];
        snprintf(mop->erroneous_option_buf, sizeof mop->erroneous_option_buf, "-%c", short_name);
        mop->erroneous_option = mop->erroneous_option_buf;
      } else {
        mop->erroneous_option = mop->argv[mop->argind];
      }
      mop->state = MopState_Done;
      return false;
    }

    if (mop->short_opt_index > 0) {
      // We're in the middle of a short-opt string.
      mop->opt_active = true;
      return true;
    }

    // argc == 0 (no command name) is a special case. There isn't much an
    // argument parser can do in that situation, so we just finish up.
    if (mop->argc == 0) {
      mop->state = MopState_Done;
      return false;
    }

    // Process the next argument.
    mop->argind++;
    if (mop->argind >= mop->argc) {
      mop->state = MopState_Done;
      return false;
    }

    char *arg = mop->argv[mop->argind];

    if (arg[0] != '-') {
      // Not an option.
      mop->state = MopState_Done;
      return false;
    }
    if (arg[1] == '\0') {
      // Plain "-" isn't treated as an option.
      mop->state = MopState_Done;
      return false;
    }

    if (arg[1] == '-') {
      if (arg[2] == '\0') {
        // "--" means future arguments aren't options.
        mop->argind++;
        mop->state = MopState_Done;
        return false;
      } else {
        // Long option.
        mop->opt_active = true;
        return true;
      }
    }

    // Short option.
    mop->opt_active = true;
    mop->short_opt_index = 1;
    return true;
  } else if (mop->state == MopState_Done) {
    return false;
  }

  assert(!"invalid state");
  return false;
}

// String option descriptions are probably just unnecessary now.
static inline
MopOptInfo mop__parse_opt_desc(char *opt_desc, char *help) {
  MopOptInfo info = {.name = opt_desc};

  char *p;
  for (p = opt_desc; *p; p++) {
    if (*p == '\'') {
      info.name_len = p - info.name;
      p++;
      info.short_name = *p;
      assert(info.short_name);
    } else if (*p == ':') {
      if (!info.short_name) info.name_len = p - info.name;
      info.optarg_name = p + 1;
      info.has_arg = true;
    }
  }

  if (!info.name_len) {
    info.name_len = p  - info.name;
  }

  info.help = help;

  return info;
}

bool mop_option_str(Mop *mop, char *opt_desc, char *help) {
  if (mop->error || (mop->state == MopState_Active && !mop->opt_active)) {
    // Skip parsing when unnecessary.
    return false;
  }
  MopOptInfo info = mop__parse_opt_desc(opt_desc, help);
  return mop_option(mop, info);
}

bool mop_option(Mop *mop, MopOptInfo info) {
  if (mop->error) return false;
  if (mop->state == MopState_GatheringUsageInfo) {
    if (info.name && info.name_len == 0) {
      info.name_len = strlen(info.name);
    }
    if (mop->usage_infos_len >= mop->usage_infos_cap) {
      assert(!"usage info buffer overflow");
      return false;
    }
    mop->usage_infos[mop->usage_infos_len].type = MopUsageInfoType_OptInfo;
    mop->usage_infos[mop->usage_infos_len].opt_info = info;
    mop->usage_infos_len++;
    return false;
  }
  if (mop->state != MopState_Active) return false;
  if (!mop->opt_active) return false;

  if (info.name && info.name_len == 0) {
    info.name_len = strlen(info.name);
  }

  char *arg = mop->argv[mop->argind];

  if (mop->short_opt_index > 0) {
    // Short option.
    assert(arg[mop->short_opt_index] != '\0');
    if (arg[mop->short_opt_index] != info.short_name) return false;

    // Increment short_opt_index here, instead of in mop_next, because we want
    // to handle the {"-ofoo"} and {"-o", "foo"} cases.
    mop->short_opt_index++;
    if (info.has_arg) {
      if (arg[mop->short_opt_index] == '\0') {
        mop->short_opt_index = 0;
        mop->argind++;
        if (mop->argind >= mop->argc) {
          mop->error = MopError_MissingOptarg;
          snprintf(mop->erroneous_option_buf, sizeof mop->erroneous_option_buf, "-%c", info.short_name);
          mop->erroneous_option = mop->erroneous_option_buf;
          mop->opt_active = false;
          return false;
        }
        mop->optarg = mop->argv[mop->argind];
      } else {
        mop->optarg = arg + mop->short_opt_index;
        mop->short_opt_index = 0;
      }
      mop->opt_active = false;
      return true;
    } else {
      if (arg[mop->short_opt_index] == '\0')
        mop->short_opt_index = 0;
      mop->opt_active = false;
      mop->optarg = 0;
      return true;
    }
  }

  // Long option.
  assert(arg[0] == '-' && arg[1] == '-');
  char *arg_long_name = arg + 2;
  char *optarg_sep = strchr(arg_long_name, '=');
  int arg_long_name_len =
    optarg_sep ? optarg_sep - arg_long_name : strlen(arg_long_name);

  bool option_name_matches =
    arg_long_name_len == info.name_len &&
    memcmp(arg_long_name, info.name, arg_long_name_len) == 0;
  if (!option_name_matches) {
    return false;
  }

  if (!info.has_arg) {
    if (optarg_sep) {
      mop->error = MopError_ExtranousOptarg;
      mop->erroneous_option = arg;
      return false;
    }
    mop->opt_active = false;
    mop->optarg = 0;
    return true;
  }

  // Handle optarg.
  if (optarg_sep) {
    mop->optarg = optarg_sep + 1;
    mop->opt_active = false;
    return true;
  }

  if (mop->argind + 1 < mop->argc) {
    mop->argind++;
    mop->optarg = mop->argv[mop->argind];
    mop->opt_active = false;
    return true;
  } else {
    mop->error = MopError_MissingOptarg;
    mop->erroneous_option = arg;
    mop->opt_active = false;
    return false;
  }
}

void mop_usage_text(Mop *mop, const char *text) {
  bool can_add_usage =
    (mop->state == MopState_Unstarted && mop->usage_infos) ||
    mop->state == MopState_GatheringUsageInfo;

  if (!can_add_usage) {
    return;
  }

  if (mop->usage_infos_len >= mop->usage_infos_cap) {
    assert(!"usage info buffer overflow");
    return;
  }
  mop->usage_infos[mop->usage_infos_len].type = MopUsageInfoType_Text;
  mop->usage_infos[mop->usage_infos_len].text = text;
  mop->usage_infos_len++;
}

void mop_print_usage(Mop *mop, FILE *file) {
  // TODO: This will do way too many write calls if the file is unbuffered (e.g.
  // stderr).

  // TODO: A version of this that doesn't use FILE * would be nice.

  // Get the longest option name length, to align the help text.
  int longest_long_name_len = 0;
  for (int i = 0; i < mop->usage_infos_len; i++) {
    if (mop->usage_infos[i].type != MopUsageInfoType_OptInfo) continue;
    MopOptInfo *opt_info = &mop->usage_infos[i].opt_info;
    if (!opt_info->help || *opt_info->help == '\n') continue;

    int this_option_len = opt_info->name_len;
    if (opt_info->has_arg) {
      this_option_len += 1;
      this_option_len += opt_info->optarg_name ? strlen(opt_info->optarg_name)
                                               : strlen("ARG");
    }
    if (longest_long_name_len < this_option_len) {
      longest_long_name_len = this_option_len;
    }
  }
  int inline_help_text_column = longest_long_name_len + 10;

  for (int i = 0; i < mop->usage_infos_len; i++) {
    MopUsageInfo *info = &mop->usage_infos[i];
    switch (info->type) {
    case MopUsageInfoType_OptInfo: {
      MopOptInfo *opt_info = &info->opt_info;
      bool has_short = opt_info->short_name;
      bool has_long = opt_info->name;
      if (!has_short && !has_long) {
        // No name? Skip.
        break;
      }
      int line_len = 0;
      if (has_short) {
        line_len += fprintf(file, "  -%c", opt_info->short_name);
      } else {
        line_len += fprintf(file, "    ");
      }
      if (has_short && has_long) {
        line_len += fprintf(file, ", ");
      } else {
        line_len += fprintf(file, "  ");
      }
      if (has_long) {
        line_len += fprintf(file, "--%.*s",
                            (int) info->opt_info.name_len, info->opt_info.name);
        if (opt_info->has_arg) {
          const char *arg_name = opt_info->optarg_name ? opt_info->optarg_name : "ARG";
          line_len += fprintf(file, "=%s", arg_name);
        }
      }
      if (opt_info->help) {
        const char *s = opt_info->help;
        int text_column = inline_help_text_column;

        // If the text starts with a newline, there's no need to align
        // it to longest option name.
        if (opt_info->help[0] == '\n') {
          text_column = 10;
        }

        while (1) {
          int required_padding = text_column - line_len;
          for (int j = 0; j < required_padding; j++) {
            fputc(' ', file);
          }

          const char *end = strchr(s, '\n');
          if (!end) {
            // Print the rest of the text.
            fprintf(file, "%s", s);
            break;
          }

          // Print text up to the next newline.
          fwrite(s, 1, end - s, file);
          fputc('\n', file);
          s = end + 1;
          line_len = 0;
        }
      }
      fputc('\n', file);
      break;
    }
    case MopUsageInfoType_Text: {
      fprintf(file, "%s", info->text);
      break;
    }
    default:
      assert(!"unknown usage info type");
      break;
    }
  }
}

static const char *mop_error_string_table[] = {
  "",
  "unknown option",
  "missing argument for option",
  "extraneous argument for option",
};

const char *mop_error_string(MopError error) {
  return mop_error_string_table[error];
}

#endif
