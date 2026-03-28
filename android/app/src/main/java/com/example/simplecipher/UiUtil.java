package com.example.simplecipher;

import android.app.Activity;
import android.content.Context;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;

final class UiUtil {
  private UiUtil() {}

  static void hideSystemKeyboard(Activity activity, EditText field) {
    InputMethodManager imm =
        (InputMethodManager) activity.getSystemService(Context.INPUT_METHOD_SERVICE);
    if (imm != null) imm.hideSoftInputFromWindow(field.getWindowToken(), 0);
  }
}
