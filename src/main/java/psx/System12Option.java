package psx;

import java.awt.Component;

import javax.swing.JCheckBox;

import ghidra.app.util.Option;

public class System12Option extends Option {
	
	private boolean selected = false;
	private JCheckBox editor = new JCheckBox();

	public System12Option(String name, Object value, Class<?> valueClass, String arg) {
		super(name, valueClass, value, arg, null);
		
		if (value instanceof Boolean) {
			selected = (Boolean)value;
		} else if (value instanceof String) {
			selected = Boolean.parseBoolean((String)value);
		}
		
		editor.setSelected(selected);
		editor.addItemListener(e -> {
			selected = editor.isSelected();
			System12Option.super.setValue(selected);
		});
	}

	@Override
	public Component getCustomEditorComponent() {
		return editor;
	}

	@Override
	public Option copy() {
		return new System12Option(getName(), getValue(), getValueClass(), getArg());
	}

	@Override
	public Object getValue() {
		return selected;
	}

	@Override
	public Class<?> getValueClass() {
		return Boolean.class;
	}
}

